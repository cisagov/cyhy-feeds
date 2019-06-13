#!/usr/bin/env python
'''Create compressed, encrypted, signed extract file with Federal CyHy
data for integration with the Weathermap project.

Usage:
  COMMAND_NAME [--cyhy-config CYHY_CONFIG] [--scan-config SCAN_CONFIG] [--assessment-config ASSESSMENT_CONFIG] [-v | --verbose] [-a | --aws] --config CONFIG_FILE [--date DATE]
  COMMAND_NAME (-h | --help)
  COMMAND_NAME --version

Options:
  -h --help                                                         Show this screen
  --version                                                         Show version
  -x CYHY_CONFIG --cyhy-config=CYHY_CONFIG                          CyHy MongoDB configuration to use
  -y SCAN_CONFIG --scan-config=SCAN_CONFIG                          Scan MongoDB configuration to use
  -z ASSESSMENT_CONFIG --assessment-config=ASSESSMENT_CONFIG        Assessment MongoDB configuration to use
  -v --verbose                                                      Show verbose output
  -a --aws                                                          Output results to s3 bucket
  -c CONFIG_FILE --config=CONFIG_FILE                               Configuration file for this script
  -d DATE --date=DATE                                               Specific date to export data from in form: %Y-%m-%d (eg. 2018-12-31) NOTE that this date is in UTC

'''

import re
import sys
from ConfigParser import SafeConfigParser
from datetime import datetime
from dateutil.relativedelta import relativedelta
import dateutil.tz as tz
from docopt import docopt
import boto3
import gnupg    # pip install python-gnupg
import os
import json
import bson
import netaddr
import pymongo
from pytz import timezone
import subprocess
import tarfile
import time
from mongo_db_from_config import db_from_config
from dmarc import get_dmarc_data

BUCKET_NAME = 'ncats-moe-data'
DOMAIN = 'ncats-moe-data'
HEADER = ''
MAX_ENTRIES = 10
DEFAULT_ES_RETRIEVE_SIZE = 10000
DAYS_OF_DMARC_REPORTS = 1
PAGE_SIZE = 100000  # Number of documents per query


def custom_json_handler(obj):
    """ Format a provided JSON object. """
    if hasattr(obj, 'isoformat'):
        return obj.isoformat()
    elif type(obj) == bson.objectid.ObjectId:
        return repr(obj)
    elif type(obj) == netaddr.IPAddress:
        return str(obj)
    elif type(obj) == netaddr.IPNetwork:
        return str(obj)
    elif type(obj) == netaddr.IPSet:
        return obj.iter_cidrs()
    else:
        raise TypeError('Object of type %s with value of %s is not JSON serializable' % (type(obj), repr(obj)))


def to_json(obj):
    """ Return a string representation of a formatted JSON. """
    return json.dumps(obj, sort_keys=True, indent=4, default=custom_json_handler)


def update_bucket(bucket_name, local_file, remote_file_name):
    '''update the s3 bucket with the new contents'''

    s3 = boto3.client('s3')

    s3.upload_file(local_file, bucket_name, remote_file_name)


def create_dummy_files(output_dir):
    ''' Used for testing cleanup routine below '''
    for n in range(1, 21):
        dummy_filename = 'dummy_file_{!s}.gpg'.format(n)
        full_path_dummy_filename = os.path.join(output_dir, dummy_filename)
        subprocess.call(['touch', full_path_dummy_filename])
        st = os.stat(full_path_dummy_filename)
        # Set file modification time to n days earlier than it was.
        # Note that there are 86400 seconds per day.
        os.utime(full_path_dummy_filename,
                 (st.st_atime, st.st_mtime - (86400 * n)))


def cleanup_old_files(output_dir, file_retention_num_days):
    '''Deletes *.gpg files older than file_retention_num_days in the
specified output_dir'''
    now_unix = time.time()
    for filename in os.listdir(output_dir):
        # We only care about filenames that end with .gpg
        if re.search('.gpg$', filename):
            full_path_filename = os.path.join(output_dir, filename)
            # If file modification time is older than
            # file_retention_num_days.  Note that there are 86400
            # seconds per day.
            file_retention_in_secs = file_retention_num_days * 86400
            if os.stat(full_path_filename).st_mtime < now_unix - file_retention_in_secs:
                # Delete file locally
                os.remove(full_path_filename)


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


def query_data(collection, query, tbz_file, tbz_filename,
               end_of_data_collection):
    print('Fetching from', collection.name, 'collection...')
    json_filename = '{!s}_{!s}.json'.format(collection.name,
                                            end_of_data_collection.isoformat().replace(':', '').split('.')[0])
    collection_file = open(json_filename, 'w')
    # How many documents into a query that will be skipped
    skips = 0
    # Number of documents in a query
    count = collection.find(query, {'key': False}).count()
    while skips < count:
        # Pull documents between n and n + 100000
        collection_file.write(to_json(list(collection.find(query, {'key': False}).skip(skips).limit(PAGE_SIZE))))
        skips += PAGE_SIZE
    collection_file.close()
    if count > PAGE_SIZE:
        # The first sed removes the ][ created by chunking the queries
        # then the 2nd sed adds , to the document at the end of a
        # chunked list
        # If on MAC you will need gsed and gawk.
        os.system('sed -i "/\]\[/d" %s ; sed -i "s/\}$/\}\,/g" %s ; ' % (json_filename, json_filename))
        # The previous sed will leave a }, at the last document in the
        # list which is removed with this aws_access_key_id
        os.system('''awk 'NR==FNR{tgt=NR-1;next} (FNR==tgt) && /\},/ { $1="    }" } 1' %s %s > %s.bak''' % (json_filename, json_filename, json_filename))
        # This is a workaround for inplace
        os.system('mv %s.bak %s' % (json_filename, json_filename))
    print('Finished writing ', collection.name, ' to file.')
    tbz_file.add(json_filename)
    print(' Added {!s} to {!s}'.format(json_filename, tbz_filename))
    # Delete file once added to tar
    if os.path.exists(json_filename):
        os.remove(json_filename)
        print('Deleted ', json_filename, ' as part of cleanup.')


def main():
    global __doc__
    __doc__ = re.sub('COMMAND_NAME', __file__, __doc__)
    args = docopt(__doc__, version='v0.0.1')
    if args['--cyhy-config']:
        cyhy_db = db_from_config(args['--cyhy-config'])
    if args['--scan-config']:
        scan_db = db_from_config(args['--scan-config'])
    if args['--assessment-config']:
        assessment_db = db_from_config(args['--assessment-config'])
    now = datetime.now(tz.tzutc())
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
    # Files older than this are deleted by cleanup_old_files()
    FILE_RETENTION_NUM_DAYS = int(config.get('DEFAULT',
                                             'FILE_RETENTION_NUM_DAYS'))
    ES_REGION = config.get('DMARC', 'ES_REGION')
    ES_URL = config.get('DMARC', 'ES_URL')
    ES_RETRIEVE_SIZE = config.get('DMARC', 'ES_RETRIEVE_SIZE')
    ES_AWS_CONFIG_SECTION_NAME = config.get('DMARC',
                                            'ES_AWS_CONFIG_SECTION_NAME')

    # Check if OUTPUT_DIR exists; if not, bail out
    if not os.path.exists(OUTPUT_DIR):
        print('''ERROR: Output directory '{!s}' does not exist - exiting!'''.format(OUTPUT_DIR))
        sys.exit(1)

    # Set up GPG (used for encrypting and signing)
    gpg = gnupg.GPG(gpgbinary='gpg2', gnupghome=GNUPG_HOME,
                    verbose=args['--verbose'],
                    options=[
                        '--pinentry-mode',
                        'loopback',
                        '-u',
                        SIGNER
                    ])
    gpg.encoding = 'utf-8'

    if args['--date']:
        # Note this date is in UTC timezone
        date_of_data = datetime.strptime(args['--date'], '%Y-%m-%d')
        start_of_data_collection = timezone('UTC').localize(date_of_data) + relativedelta(days=-1, hour=0, minute=0, second=0, microsecond=0)
        end_of_data_collection = start_of_data_collection + relativedelta(days=1)
    else:
        start_of_data_collection = now + relativedelta(days=-1, hour=0, minute=0, second=0, microsecond=0)
        end_of_data_collection = start_of_data_collection + relativedelta(days=1)

    # Get a list of all non-retired orgs
    org_filter = {
            '_id': {'$ne': 'ROOT'},
            'retired': {'$ne': True}
    }
    all_orgs = cyhy_db['requests'].find(org_filter, {'_id': 1}).distinct('_id')
    orgs = list(set(all_orgs) - ORGS_EXCLUDED)

    # Create tar/bzip2 file for writing
    tbz_filename = 'cyhy_extract_{!s}.tbz'.format(end_of_data_collection.isoformat().replace(':', '').split('.')[0])
    tbz_file = tarfile.open(tbz_filename, mode='w:bz2')

    cyhy_collection = {
        'host_scans': {
            'owner': {
                '$in': orgs
            },
            'time': {
                '$gte': start_of_data_collection,
                '$lt': end_of_data_collection
            }
        },
        'port_scans': {
            'owner': {
                '$in': orgs
            },
            'time': {
                '$gte': start_of_data_collection,
                '$lt': end_of_data_collection
            }
        },
        'vuln_scans': {
            'owner': {
                '$in': orgs
            },
            'time': {
                '$gte': start_of_data_collection,
                '$lt': end_of_data_collection
            }
        },
        'hosts': {
            'owner': {
                '$in': orgs
            },
            'last_change': {
                '$gte': start_of_data_collection,
                '$lt': end_of_data_collection
            }
        },
        'tickets': {
            'owner': {
                '$in': orgs
            },
            'last_change': {
                '$gte': start_of_data_collection,
                '$lt': end_of_data_collection
            }
        }
    }

    scan_collection = {
        'https_scan': {
            'scan_date': {
                '$gte': start_of_data_collection,
                '$lt': end_of_data_collection
            }
        },
        'sslyze_scan': {
            'scan_date': {
                '$gte': start_of_data_collection,
                '$lt': end_of_data_collection
            }
        },
        'trustymail': {
            'scan_date': {
                '$gte': start_of_data_collection,
                '$lt': end_of_data_collection
            }
        },
        'certs': {
            'sct_or_not_before': {
                '$gte': start_of_data_collection,
                '$lt': end_of_data_collection
            }
        }
    }

    assessment_collection = {
        'assessments': {},
        'findings': {}
    }

    if args['--cyhy-config']:
        for collection in cyhy_collection:
            query_data(cyhy_db[collection], cyhy_collection[collection],
                       tbz_file, tbz_filename, end_of_data_collection)
    if args['--scan-config']:
        for collection in scan_collection:
            query_data(scan_db[collection], scan_collection[collection],
                       tbz_file, tbz_filename, end_of_data_collection)
    if args['--assessment-config']:
        for collection in assessment_collection:
            query_data(assessment_db[collection],
                       assessment_collection[collection],
                       tbz_file, tbz_filename, end_of_data_collection)

    # Note that we use the elasticsearch AWS profile here
    json_data = to_json(get_dmarc_data(ES_REGION, ES_URL,
                                            DAYS_OF_DMARC_REPORTS,
                                            ES_RETRIEVE_SIZE,
                                            ES_AWS_CONFIG_SECTION_NAME))
    json_filename = '{!s}_{!s}.json'.format('DMARC',
                                            end_of_data_collection.isoformat().replace(':', '').split('.')[0])
    dmarc_file = open(json_filename, 'w')
    dmarc_file.write(json_data)
    dmarc_file.close()
    tbz_file.add(json_filename)
    tbz_file.close()
    if os.path.exists(json_filename):
        os.remove(json_filename)
        print('Deleted ', json_filename, ' as part of cleanup.')

    gpg_file_name = tbz_filename + '.gpg'
    gpg_full_path_filename = os.path.join(OUTPUT_DIR, gpg_file_name)
    # Encrypt (with public keys for all RECIPIENTS) and sign (with
    # SIGNER's private key)
    with open(tbz_filename, 'rb') as f:
        status = gpg.encrypt_file(f, RECIPIENTS, armor=False, sign=SIGNER,
                                  passphrase=SIGNER_PASSPHRASE,
                                  output=gpg_full_path_filename)

    if not status.ok:
        print('\nFAILURE - GPG ERROR!\n GPG status: {!s} \n GPG stderr:\n{!s}'.format(status.status, status.stderr))
        sys.exit(-1)

    if args['--aws']:
        # send the contents to the s3 bucket
        update_bucket(BUCKET_NAME, gpg_full_path_filename, gpg_file_name)
        print('Upload to AWS bucket complete')
    print('Encrypted, signed, compressed JSON data written to file: {!s}'.format(gpg_full_path_filename))

    if os.path.exists(tbz_filename):
        os.remove(tbz_filename)
        print('Deleted ', tbz_filename, ' as part of cleanup.')

    cleanup_old_files(OUTPUT_DIR, FILE_RETENTION_NUM_DAYS)

    print('\nSUCCESS!')


if __name__ == '__main__':
    main()
