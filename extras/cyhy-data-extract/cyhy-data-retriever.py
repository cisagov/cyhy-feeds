#!/usr/bin/env python3

'''Retrieve a compressed, encrypted, signed extract file and verify/decrypt/uncompress it.
   NOTES:
   * curl must be installed in order to make the https request to get the extract file
   * This script expects to operate on a GPG-encrypted bzip2 tar file: e.g. filename.tbz.gpg
   
Usage:
  COMMAND_NAME [-v | --verbose] [--filename EXTRACT_FILENAME] --config CONFIG_FILE
  COMMAND_NAME (-h | --help)
  COMMAND_NAME --version

Options:
  -h --help                                         Show this screen
  --version                                         Show version
  -f EXTRACT_FILENAME --filename=EXTRACT_FILENAME   Name of extract file to retrieve
  -v --verbose                                      Show verbose output
  -c CONFIG_FILE --config=CONFIG_FILE               Configuration file for this script

'''

import sys
import re
from docopt import docopt
import dateutil.tz as tz
from datetime import datetime
from dateutil.relativedelta import relativedelta
import gnupg    # Requires installation of GPG 2.1 (e.g. port install gnupg21) and 'python-gnupg' package (e.g. pip install python-gnupg)
import tarfile
import subprocess
from configparser import SafeConfigParser

def main():
    global __doc__    
    __doc__ = re.sub('COMMAND_NAME', __file__, __doc__)
    args = docopt(__doc__, version='v0.0.1')
    now = datetime.now(tz.tzutc())
    
    # Read parameters in from config file
    config = SafeConfigParser()
    config.read([args['--config']])
    HTTPS_HOST_EXTERNAL_IP = config.get('DEFAULT', 'HTTPS_HOST_EXTERNAL_IP')
    HTTPS_VIRTUAL_HOST_NAME = config.get('DEFAULT', 'HTTPS_VIRTUAL_HOST_NAME')
    CLIENT_CERTIFICATE_FILE = config.get('DEFAULT', 'CLIENT_CERTIFICATE_FILE')
    CLIENT_PRIVATE_KEY_FILE = config.get('DEFAULT', 'CLIENT_PRIVATE_KEY_FILE')
    GNUPG_HOME = config.get('DEFAULT', 'GNUPG_HOME')
    GPG_DECRYPTION_PASSPHRASE = config.get('DEFAULT', 'GPG_DECRYPTION_PASSPHRASE')
    
    # Set up name of file to retrieve
    if args['--filename']:      # If extract filename is provided, use that
        extract_filename = args['--filename']
    else:                       # Otherwise, look for the most-recent daily file; this must change if we start generating more than one file per day
        today = now + relativedelta(hour=0, minute=0, second=0, microsecond=0)
        extract_filename = 'cyhy_extract_{!s}.tbz.gpg'.format(today.isoformat().replace(':','').split('.')[0])
    
    # Download extract file from server
    print (('Downloading extract file:  https://{!s}/{!s}').format(HTTPS_HOST_EXTERNAL_IP, extract_filename))
    if args['--verbose']:
        print (('curl -O -k --resolve {!s}:443:{!s} https://{!s}/{!s} --cert {!s} --key {!s}').format(HTTPS_VIRTUAL_HOST_NAME, HTTPS_HOST_EXTERNAL_IP, HTTPS_VIRTUAL_HOST_NAME, extract_filename, CLIENT_CERTIFICATE_FILE, CLIENT_PRIVATE_KEY_FILE))
    subprocess.call(['curl', '-O', '-k', '--resolve', ('{!s}:443:{!s}').format(HTTPS_VIRTUAL_HOST_NAME, HTTPS_HOST_EXTERNAL_IP), ('https://{!s}/{!s}').format(HTTPS_VIRTUAL_HOST_NAME, extract_filename), '--cert', CLIENT_CERTIFICATE_FILE, '--key', CLIENT_PRIVATE_KEY_FILE])
    
    # Set filename for decrypted output
    if extract_filename[-4:] == '.gpg':
        decrypted_filename = extract_filename.split('.gpg')[0]
    else:   # If extract_filename doesn't end in '.gpg'
        decrypted_filename = extract_filename + '_decrypted'
    
    # Use GPG to verify & decrypt extract file
    # IMPORTANT: To pass in the passphrase for decryption, gpg-agent.conf in GNUPG_HOME must have: allow-loopback-pinentry
    gpg = gnupg.GPG(gpgbinary='gpg2', gnupghome=GNUPG_HOME, verbose=args['--verbose'], options=['--pinentry-mode', 'loopback'])
    extract_stream = open(extract_filename, 'rb')
    decrypted_data = gpg.decrypt_file(extract_stream, passphrase=GPG_DECRYPTION_PASSPHRASE, output=decrypted_filename)
    extract_stream.close()
    
    if not decrypted_data.ok:
        print("\nFAILURE - GPG DECRYPTION ERROR!\n GPG status: {!s} \n GPG stderr:\n{!s}".format(decrypted_data.status, decrypted_data.stderr))
        sys.exit(-1)
    
    print("Encrypted file {!s} successfully decrypted to file: {!s}".format(extract_filename, decrypted_filename))
    
    # Uncompress the tar/bzip2 (.tbz) file (decrypted_filename)
    tar = tarfile.open(decrypted_filename)
    tar_membernames = tar.getnames()
    if tar_membernames:
        print("Extracting files:")
        for f in tar_membernames:
            print(" {!s}".format(f))
        tar.extractall()
        print("Decrypted file {!s} successfully uncompressed".format(decrypted_filename))
    else:
        print("\nFAILURE - ERROR UNCOMPRESSING!\n Expected .tbz file; Invalid tar data found in {!s}".format(decrypted_filename))
        sys.exit(-1)
    tar.close()
    
    # Shell equivalent for decrypt/uncompress:  gpg -d extract_filename | tar xj
    
    # For debugging:
    # import IPython; IPython.embed()
    # sys.exit(0)
    
    print("\nSUCCESS!")
    sys.exit(1)
    
if __name__=='__main__':
    main()