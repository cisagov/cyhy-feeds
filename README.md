# Cyhy-feeds :inbox_tray: :outbox_tray:

cyhy-feeds consists of two parts; the extractor and the retriever

`cyhy-data-extract` compresses the data, signs the compressed file, encrypts the file, and pushes
the encrypted compressed file to a bucket in S3 using AWS creds.

`cyhy-data-retriever` pulls the file from s3, decrypts the file, and decompresses it.

## Getting Started ##

`cyhy-data-extract` requires **Python 2** because it uses cyhy-core which is written in Python2. Python 3 is not supported at this time.

`cyhy-data-extract` can run as either Python 2 or Python 3.

To run the tool locally first install the requirements:
```bash
pip install -r requirements.txt
```

### cyhy-data-extract Usage and Examples ###

```bash
python2.7 cyhy-data-extract.py --cyhy_section cyhy_section --scan_section scan_section --config cyhy-data-extract.cfg
python2.7 cyhy-data-extract.py --cyhy_section cyhy_section --scan_section scan_section --aws --config cyhy-data-extract.cfg
python2.7 cyhy-data-extract.py --cyhy_section cyhy_section --scan_section scan_section --aws --config cyhy-data-extract.cfg --date 2019-01-25
python2.7 cyhy-data-extract.py --cyhy_section cyhy_section --scan_section scan_section --assessment_section assessment_section --aws --config cyhy-data-extract.cfg --date 2019-01-25
```
Note: The section names are taken from the cyhy.conf

#### cyhy-data-extract Options ####

```bash
Create compressed, encrypted, signed extract file with Federal CyHy data for integration with the Weathermap project.

Usage:
  COMMAND_NAME [--cyhy_section CYHY_SECTION] [--scan_section SCAN_SECTION] [--assessment_section ASSESSMENT_SECTION] [-v | --verbose] [-f | --federal] [-a | --aws] --config CONFIG_FILE [--date DATE]
  COMMAND_NAME (-h | --help)
  COMMAND_NAME --version

Options:
  -h --help                                                         Show this screen
  --version                                                         Show version
  -x CYHY_SECTION --cyhy_section=CYHY_SECTION                       CyHy configuration section to use
  -y SCAN_SECTION --scan_section=SCAN_SECTION                       Scan configuration section to use
  -z ASSESSMENT_SECTION --assessment_section=ASSESSMENT_SECTION     Assessment configuration section to use
  -v --verbose                                                      Show verbose output
  -f --federal                                                      Returns only Federal requestDocs
  -a --aws                                                          Output results to s3 bucket
  -c CONFIG_FILE --config=CONFIG_FILE                               Configuration file for this script
  -d DATE --date=DATE                                               Specific date to export data from in form: %Y-%m-%d (eg. 2018-12-31) NOTE that this date is in UTC

```


### cyhy-data-retriever Usage and Examples ###

```bash
   cyhy-data-retriever --filename cyhy_extract_2019-01-25T000000+0000.tbz.gpg --aws --config cyhy-data-retriever.cfg
```
Note: The section names are taken from the cyhy.conf [Example](https://github.com/dhs-ncats/cyhy_amis/blob/develop/ansible/roles/cyhy_feeds/tasks/main.yml#L111-L134)

#### cyhy-data-extract Options ####

```bash
Retrieve a compressed, encrypted, signed extract file and verify/decrypt/uncompress it.
   NOTES:
   * the python modules below must be installed for the script to work
   * This script expects to operate on a GPG-encrypted bzip2 tar file: e.g. filename.tbz.gpg

Usage:
  COMMAND_NAME [-v | --verbose] [--filename EXTRACT_FILENAME] [-a | --aws] --config CONFIG_FILE
  COMMAND_NAME (-h | --help)
  COMMAND_NAME --version

Options:
  -h --help                                         Show this screen
  --version                                         Show version
  -f EXTRACT_FILENAME --filename=EXTRACT_FILENAME   Name of extract file to retrieve
  -v --verbose                                      Show verbose output
  -c CONFIG_FILE --config=CONFIG_FILE               Configuration file for this script
  -a --aws                                          Output results to s3 bucket

```

### Extract Config File Parameters ###

* `FED_ORGS_EXCLUDED` - Orgs to exclude from extract
* `GNUPG_HOME` - Location of GNUPG database (eg. /Users/bob/.gnupg)
* `RECIPIENTS` - Names on the gpg public key(s)
* `SIGNER` - Gpg signer to ensure integrity
* `SIGNER_PASSPHRASE` - Passphrase for signer gpg key
* `OUTPUT_DIR` - Directory to output extract to
* `FILE_RETENTION_NUM_DAYS` - Number of days to hold extract
* `AWS_ACCESS_KEY_ID` - User ID used for AWS S3 bucket write access
* `AWS_SECRET_ACCESS_KEY` - Key for AWS S3 bucket write access
* `ES_REGION` - Region for DMARC bucket
* `ES_URL` - Elastic search url
* `ES_RETRIEVE_SIZE` - Elastic search size

### Retriever Config File Parameters ###

* `CLIENT_PRIVATE_KEY_FILE` - Path to gpg private key
* `GNUPG_HOME` - Location of GPG database (eg. /Users/bob/.gnupg)
* `GPG_DECRYPTION_PASSPHRASE` - Passphrase for private gpg key
* `AWS_ACCESS_KEY_ID` - User ID used for AWS S3 bucket read access
* `AWS_SECRET_ACCESS_KEY` - Key for AWS S3 bucket read access
* `PROXY_CONFIG` - Only needed when proxy is present

## Public Domain ##

This project is in the worldwide [public domain](LICENSE.md).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
