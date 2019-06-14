# Cyber Hygiene Feeds 📥 📤 #

[![Build Status](https://travis-ci.com/cisagov/cyhy-feeds.svg?branch=develop)](https://travis-ci.com/cisagov/cyhy-feeds)
[![Coverage Status](https://coveralls.io/repos/github/cisagov/cyhy-feeds/badge.svg?branch=develop)](https://coveralls.io/github/cisagov/cyhy-feeds?branch=develop)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/cisagov/cyhy-feeds.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cisagov/cyhy-feeds/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/cisagov/cyhy-feeds.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/cisagov/cyhy-feeds/context:python)

cyhy-feeds consists of two parts; the extractor and the retriever

`cyhy-data-extract` retrieve and compress the specified data, sign the compressed
file, encrypt the file, and optionally push the encrypted, compressed file to an
S3 bucket using provided AWS credentials.

`cyhy-data-retriever` take a provided file (optionally stored on an S3 bucket),
decrypt it, and then decompresses it to local storage.

## Getting Started ##

`cyhy-data-extract` requires **Python 2** because it has not been updated
to remove all Python 2 requirements. Python 3 is not officially supported
at this time.

`cyhy-data-retriever` can run as either Python 2 or Python 3.

To run the tool locally first install the requirements:

```console
pip install -r requirements.txt
```

### cyhy-data-extract Usage and Examples ###

#### cyhy-data-extract Usage ####

```console
Create compressed, encrypted, signed extract file with Federal CyHy data for
integration with the Weathermap project.

Usage:
  COMMAND_NAME [--cyhy-config CYHY_CONFIG] [--scan-config SCAN_CONFIG]
    [--assessment-config ASSESSMENT_CONFIG] [-v | --verbose] [-a | --aws]
    --config CONFIG_FILE [--date DATE]
  COMMAND_NAME (-h | --help)
  COMMAND_NAME --version

Options:
  -h --help                                                       Show this screen
  --version                                                       Show version
  -x CYHY_CONFIG --cyhy-config=CYHY_CONFIG                        CyHy configuration
                                                                  file to use
  -y SCAN_CONFIG --scan-config=SCAN_CONFIG                        Scan configuration
                                                                  file to use
  -z ASSESSMENT_CONFIG --assessment-config=ASSESSMENT_CONFIG      Assessment configuration
                                                                  file to use
  -v --verbose                                                    Show verbose output
  -a --aws                                                        Output results
                                                                  to S3 bucket
  -c CONFIG_FILE --config=CONFIG_FILE                             Configuration file
                                                                  for this script
  -d DATE --date=DATE                                             Specific date to
                                                                  export data from
                                                                  in form:
                                                                  %YYYY-%MM-%DD
                                                                  (eg. 2018-12-31)
                                                                  NOTE that this
                                                                  date is in UTC

```

#### cyhy-data-extract Examples ####

Extract CyHy data for the current day using the MongoDB configuration in `cyhy.yml`
and the runtime configuration in `cyhy-data-extract.cfg`.

```console
python2.7 cyhy-data-extract.py --cyhy-config cyhy.yml --config cyhy-data-extract.cfg
```

Extract scan data for the current day using the MongoDB configuration in 'scan.yml'
and the runtime configuration in `cyhy-data-extract.cfg`.

```console
python2.7 cyhy-data-extract.py --scan-config scan.yml --config cyhy-data-extract.cfg
```

Extract assessment data for the current day using the MongoDB configuration in
`assessment.yml` and the runtime configuration in `cyhy-data-extract.cfg`.

```console
python2.7 cyhy-data-extract.py --assessment-config assessment.yml --config cyhy-data-extract.cfg
```

Extract CyHy and scan data for the current day using the MongoDB configurations
in `cyhy.yml` and `scan.yml`, respectively, and use the runtime configuration in
`cyhy-data-extract.cfg`.

```console
python2.7 cyhy-data-extract.py --cyhy-config cyhy.yml --scan-config scan.yml
  --config cyhy-data-extract.cfg
```

Extract CyHy and scan data for the current day using the MongoDB configurations
in `cyhy.yml` and `scan.yml`, upload the results to AWS, and use the runtime
configuration in `cyhy-data-extract.cfg`.

```console
python2.7 cyhy-data-extract.py --cyhy-config cyhy.yml --scan-config scan.yml
  --aws --config cyhy-data-extract.cfg
```

Extract CyHy and scan data for January 25th, 2019 using the MongoDB configurations
in `cyhy.yml` and `scan.yml`, upload the results to AWS, and use the runtime
configuration in `cyhy-data-extract.cfg`.

```console
python2.7 cyhy-data-extract.py --cyhy-config cyhy.yml --scan-config scan.yml
  --aws --config cyhy-data-extract.cfg --date 2019-01-25
```

Extract CyHy, scan, and assessment data for January 25th, 2019 using the MongoDB
configurations in `cyhy.yml`, `scan.yml`, and `assessment.yml`, upload the results
to AWS, and use the runtime configuration in `cyhy-data-extract.cfg`.

```console
python2.7 cyhy-data-extract.py --cyhy-config cyhy.yml --scan-config scan.yml
  --assessment-config assessment.yml --aws --config cyhy-data-extract.cfg
  --date 2019-01-25
```

### cyhy-data-retriever Usage and Examples ###

#### cyhy-data-retriever Usage ####

```console
Retrieve a compressed, encrypted, signed extract file and
verify/decrypt/uncompress it.

   NOTES:
   * the python modules below must be installed for the script to work
   * This script expects to operate on a GPG-encrypted bzip2 tar file
      e.g. filename.tbz.gpg

Usage:
  COMMAND_NAME [-v | --verbose] [--filename EXTRACT_FILENAME] [-a | --aws]
    --config CONFIG_FILE
  COMMAND_NAME (-h | --help)
  COMMAND_NAME --version

Options:
  -h --help                                         Show this screen
  --version                                         Show version
  -f EXTRACT_FILENAME --filename=EXTRACT_FILENAME   Name of extract file to retrieve
  -v --verbose                                      Show verbose output
  -c CONFIG_FILE --config=CONFIG_FILE               Configuration file for this script
  -a --aws                                          Output results to S3 bucket

```

#### cyhy-data-retriever Examples ####

Retrieve the data stored in file `cyhy_extract_2019-01-25T000000+0000.tbz.gpg`
residing on AWS using the runtime configuration in `cyhy-data-retriever.cfg`.

```console
  cyhy-data-retriever --filename cyhy_extract_2019-01-25T000000+0000.tbz.gpg --aws
    --config cyhy-data-retriever.cfg
```

### Extract Config File Parameters ###

* `FED_ORGS_EXCLUDED` - Orgs to exclude from extract
* `GNUPG_HOME` - Location of GNUPG database (eg. /Users/bob/.gnupg)
* `RECIPIENTS` - Names on the gpg public key(s)
* `SIGNER` - Gpg signer to ensure integrity
* `SIGNER_PASSPHRASE` - Passphrase for signer gpg key
* `OUTPUT_DIR` - Directory to output extract to
* `FILE_RETENTION_NUM_DAYS` - Number of days to hold extract
* `ES_AWS_CONFIG_SECTION_NAME` - Name of the AWS config file section
  containing the configuration to be used when accessing the
  Elasticsearch data
* `ES_REGION` - Region for DMARC bucket
* `ES_URL` - Elasticsearch URL
* `ES_RETRIEVE_SIZE` - Elasticsearch size

### Retriever Config File Parameters ###

* `CLIENT_PRIVATE_KEY_FILE` - Path to gpg private key
* `GNUPG_HOME` - Location of GPG database (eg. /Users/bob/.gnupg)
* `GPG_DECRYPTION_PASSPHRASE` - Passphrase for private gpg key
* `AWS_ACCESS_KEY_ID` - User ID used for AWS S3 bucket read access
* `AWS_SECRET_ACCESS_KEY` - Key for AWS S3 bucket read access
* `PROXY_CONFIG` - Only needed when proxy is present

## Contributing ##

We welcome contributions!  Please see [here](CONTRIBUTING.md) for
details.

## License ##

This project is in the worldwide [public domain](LICENSE.md).

This project is in the public domain within the United States, and
copyright and related rights in the work worldwide are waived through
the [CC0 1.0 Universal public domain
dedication](https://creativecommons.org/publicdomain/zero/1.0/).

All contributions to this project will be released under the CC0
dedication. By submitting a pull request, you are agreeing to comply
with this waiver of copyright interest.
