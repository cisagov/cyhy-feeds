#!/usr/bin/env python

'''Create compressed, encrypted, signed extract file with Federal CyHy data for integration with the Weathermap project.

Usage:
  COMMAND_NAME [--section SECTION] [-v | --verbose] [-f | --federal] [-a | --aws] --config CONFIG_FILE
  COMMAND_NAME (-h | --help)
  COMMAND_NAME --version

Options:
  -h --help                             Show this screen
  --version                             Show version
  -s SECTION --section=SECTION          CyHy configuration section to use
  -v --verbose                          Show verbose output
  -f --federal                          Returns only Federal requestDocs
  -a --aws                              Output results to s3 bucket
  -c CONFIG_FILE --config=CONFIG_FILE   Configuration file for this script

'''

import sys
import re
from ConfigParser import SafeConfigParser
from datetime import datetime
from dateutil.relativedelta import relativedelta
from docopt import docopt
import boto3
import cStringIO
import gnupg    # pip install python-gnupg
import os
import subprocess
import tarfile
import time
from cyhy.db import database
from cyhy.util import util

BUCKET_NAME = 'ncats-moe-data'
DOMAIN = 'ncats-moe-data'
HEADER = ''
MAX_ENTRIES = 1


def update_bucket(bucket_name, bucket_contents, local_file, remote_file_name, aws_access_key_id, aws_secret_access_key):
    '''update the s3 bucket with the new contents'''

    s3 = boto3.client(
        's3',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )

    s3.upload_file(local_file, bucket_name, remote_file_name)


def create_dummy_files(output_dir):
    ''' Used for testing cleanup routine below '''
    for n in range(1,21):
        dummy_filename = 'dummy_file_{!s}.gpg'.format(n)
        full_path_dummy_filename = os.path.join(output_dir, dummy_filename)
        subprocess.call(['touch', full_path_dummy_filename])
        st = os.stat(full_path_dummy_filename)
        # Set file modification time to n days earlier than it was
        os.utime(full_path_dummy_filename, (st.st_atime, st.st_mtime - (86400 * n)))        # 86400 seconds per day


def cleanup_old_files(output_dir, file_retention_num_days):
    ''' Deletes *.gpg files older than file_retention_num_days in the specified output_dir'''
    now_unix = time.time()
    for filename in os.listdir(output_dir):
        if re.search('.gpg$', filename):        # We only care about filenames that end with .gpg
            full_path_filename = os.path.join(output_dir, filename)
            # If file modification time is older than file_retention_num_days
            if os.stat(full_path_filename).st_mtime < now_unix - (file_retention_num_days * 86400):     # 86400 seconds per day
                os.remove(full_path_filename)   # Delete file locally


# TODO Finish function to delete files until there is only X in the bucket
def cleanup_bucket_files(aws_access_key_id, aws_secret_access_key):
    # Deletes oldest file if there are more than ten files in the bucket_name
    s3 = boto3.client(
        's3',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )

    if(len(s3.list_objects(Bucket=BUCKET_NAME)['Contents']) > MAX_ENTRIES):
        for key in s3.list_objects(Bucket=BUCKET_NAME)['Contents']:
            print(key)
            print(key['LastModified'])


def main():
    global __doc__
    __doc__ = re.sub('COMMAND_NAME', __file__, __doc__)
    args = docopt(__doc__, version='v0.0.1')
    db = database.db_from_config(args['--section'])
    now = util.utcnow()
    now_unix = time.time()
    # import IPython; IPython.embed() #<<< BREAKPOINT >>>
    # sys.exit(0)

    # Read parameters in from config file
    config = SafeConfigParser()
    config.read([args['--config']])
    ORGS_EXCLUDED = set(config.get('DEFAULT', 'FED_ORGS_EXCLUDED').split(','))
    if ORGS_EXCLUDED == {''}:
        ORGS_EXCLUDED = set()
    GNUPG_HOME = config.get('DEFAULT', 'GNUPG_HOME')
    RECIPIENTS = config.get('DEFAULT', 'RECIPIENTS').split(',')
    SIGNER = config.get('DEFAULT', 'SIGNER')
    SIGNER_PASSPHRASE = config.get('DEFAULT', 'SIGNER_PASSPHRASE')
    OUTPUT_DIR = config.get('DEFAULT', 'OUTPUT_DIR')
    FILE_RETENTION_NUM_DAYS = int(config.get('DEFAULT', 'FILE_RETENTION_NUM_DAYS'))  # Files older than this are deleted by cleanup_old_files()
    AWS_ACCESS_KEY_ID = config.get('DEFAULT', 'AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = config.get('DEFAULT', 'AWS_SECRET_ACCESS_KEY')


    # Check if OUTPUT_DIR exists; if not, bail out
    if not os.path.exists(OUTPUT_DIR):
        print "ERROR: Output directory '{!s}' does not exist - exiting!".format(OUTPUT_DIR)
        sys.exit(1)

    # create_dummy_files(OUTPUT_DIR)

    # Set up GPG (used for encrypting and signing)
    gpg = gnupg.GPG(gpgbinary='gpg2', gnupghome=GNUPG_HOME, verbose=args['--verbose'], options=['--pinentry-mode', 'loopback', '-u', SIGNER])
    gpg.encoding = 'utf-8'

    yesterday = now + relativedelta(days=-1, hour=0, minute=0, second=0, microsecond=0)
    today = yesterday + relativedelta(days=1)

    if args['--federal']:
        all_fed_descendants = db.RequestDoc.get_all_descendants('FEDERAL')
        orgs = list(set(all_fed_descendants) - ORGS_EXCLUDED)
    else:
        all_orgs = db.RequestDoc.get_all_descendants('ROOT')
        orgs = list(set(all_orgs) - ORGS_EXCLUDED)

    # Create tar/bzip2 file (in memory only) for writing
    tbz_filename = 'cyhy_extract_{!s}.tbz'.format(today.isoformat().replace(':','').split('.')[0])
    mem_file = cStringIO.StringIO()
    tbz_file = tarfile.open(mode='w:bz2', fileobj=mem_file)

    for (collection, query) in [(db.host_scans, {'owner':{'$in':orgs}, 'time':{'$gte':yesterday, '$lt':today}}),
                                (db.port_scans, {'owner':{'$in':orgs}, 'time':{'$gte':yesterday, '$lt':today}}),
                                (db.vuln_scans, {'owner':{'$in':orgs}, 'time':{'$gte':yesterday, '$lt':today}}),
                                (db.hosts, {'owner':{'$in':orgs}, 'last_change':{'$gte':yesterday, '$lt':today}}),
                                (db.tickets, {'owner':{'$in':orgs}, 'last_change':{'$gte':yesterday, '$lt':today}})]:
        print "Fetching from", collection.name, "collection...",
        # data = list(collection.find(query, {'key':False}).limit(100))      # For testing
        data = list(collection.find(query, {'key':False}))

        json_data = util.to_json(data)
        json_filename = '{!s}_{!s}.json'.format(collection.name, today.isoformat().replace(':','').split('.')[0])

        # Build up tarinfo object for json file, then add it to the .tbz archive
        tarinfo = tarfile.TarInfo(json_filename)
        tarinfo.size = len(json_data)
        tarinfo.mtime = now_unix
        tbz_file.addfile(tarinfo, cStringIO.StringIO(json_data))
        print " Added {!s} to {!s}".format(json_filename, tbz_filename)

    tbz_file.close()
    mem_file.seek(0)    # Be kind, rewind

    # Encrypt (with public keys for all RECIPIENTS) & sign (with SIGNER's private key)
    encrypted_signed_data = gpg.encrypt_file(mem_file, RECIPIENTS, armor=False, sign=SIGNER, passphrase=SIGNER_PASSPHRASE)

    if not encrypted_signed_data.ok:
        print("\nFAILURE - GPG ERROR!\n GPG status: {!s} \n GPG stderr:\n{!s}".format(encrypted_signed_data.status, encrypted_signed_data.stderr))
        sys.exit(-1)

    # Output the compressed, encrypted, signed file as a .gpg
    gpg_file_name = tbz_filename + '.gpg'
    gpg_full_path_filename = os.path.join(OUTPUT_DIR, gpg_file_name)
    output_file = open(gpg_full_path_filename, 'wb')

    if args['--aws']:
        bucket_contents = encrypted_signed_data.data
        output_file.write(encrypted_signed_data.data)
        output_file.close()

        # send the contents to the s3 bucket
        update_bucket(BUCKET_NAME, bucket_contents, gpg_full_path_filename, gpg_file_name, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

        print('Upload to AWS bucket complete')
    else:
        output_file.write(encrypted_signed_data.data)
        output_file.close()
    print("Encrypted, signed, compressed JSON data written to file: {!s}".format(gpg_full_path_filename))



    cleanup_old_files(OUTPUT_DIR, FILE_RETENTION_NUM_DAYS)

    print("\nSUCCESS!")

if __name__=='__main__':
    main()
