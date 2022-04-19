#!/usr/bin/env python
"""Create compressed, encrypted, signed extract file with Federal CyHy data for integration with the Weathermap project.

Usage:
  COMMAND_NAME --config CONFIG_FILE [--cyhy-config CYHY_CONFIG] [--scan-config SCAN_CONFIG] [--assessment-config ASSESSMENT_CONFIG] [-v | --verbose] [-a | --aws ] [--cleanup-aws] [--date DATE] [--debug]
  COMMAND_NAME (-h | --help)
  COMMAND_NAME --version

Options:
  -h --help                                                         Show this screen
  --version                                                         Show version
  -x CYHY_CONFIG --cyhy-config=CYHY_CONFIG                          CyHy MongoDB configuration to use
  -y SCAN_CONFIG --scan-config=SCAN_CONFIG                          Scan MongoDB configuration to use
  -z ASSESSMENT_CONFIG --assessment-config=ASSESSMENT_CONFIG        Assessment MongoDB configuration to use
  -v --verbose                                                      Show verbose output
  -a --aws                                                          Output results to S3 bucket
  --cleanup-aws                                                     Delete old files from the S3 bucket
  -c CONFIG_FILE --config=CONFIG_FILE                               Configuration file for this script
  -d DATE --date=DATE                                               Specific date to export data from in form: %Y-%m-%d (eg. 2018-12-31) NOTE that this date is in UTC
  --debug                                                           Enable debug logging

"""

# Standard Python Libraries
from datetime import datetime
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import sys
import tarfile
import time

# Third-Party Libraries
import boto3
import bson
from dateutil.relativedelta import relativedelta
import dateutil.tz as tz
from docopt import docopt
import gnupg  # pip install python-gnupg
import netaddr
from pytz import timezone

# cisagov Libraries
from dmarc import get_dmarc_data
from mongo_db_from_config import db_from_config

# Import the appropriate version of SafeConfigParser.
if sys.version_info.major == 2:
    # Third-Party Libraries
    from ConfigParser import SafeConfigParser
else:
    # Standard Python Libraries
    from configparser import SafeConfigParser

# Logging core variables
logger = logging.getLogger("cyhy-feeds")
LOG_FILE_NAME = "/var/log/cyhy/feeds.log"
LOG_FILE_MAX_SIZE = pow(1024, 2) * 128
LOG_FILE_BACKUP_COUNT = 9
DEFAULT_LOGGER_LEVEL = logging.INFO

BUCKET_NAME = "ncats-moe-data"
DOMAIN = "ncats-moe-data"
HEADER = ""
DEFAULT_ES_RETRIEVE_SIZE = 10000
DAYS_OF_DMARC_REPORTS = 1
PAGE_SIZE = 100000  # Number of documents per query
SAVEFILE_PREFIX = "cyhy_extract_"


def custom_json_handler(obj):
    """Format a provided JSON object."""
    if hasattr(obj, "isoformat"):
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
        raise TypeError(
            "Object of type {} with value of {} is not JSON serializable".format(
                type(obj), repr(obj)
            )
        )


def to_json(obj):
    """Return a string representation of a formatted JSON."""
    return json.dumps(obj, sort_keys=True, indent=4, default=custom_json_handler)


def flatten_datetime(in_datetime):
    """Flatten datetime to day, month, and year only."""
    return in_datetime.replace(hour=0, minute=0, second=0, microsecond=0)


# All logging code is pulled from cyhy-core and tweaked down to this single use-case.
# Since we are still running Python2 we cannot leverage some of the improvements
# made in the logging library in later version.
def setup_logging(debug_logging):
    """Set up logging for the script."""
    LOGGER_FORMAT = "%(asctime)-15s %(levelname)s %(name)s - %(message)s"
    formatter = logging.Formatter(LOGGER_FORMAT)
    formatter.converter = time.gmtime  # log times in UTC
    root = logging.getLogger()
    if debug_logging:
        root.setLevel(logging.DEBUG)
    else:
        root.setLevel(DEFAULT_LOGGER_LEVEL)
    file_handler = RotatingFileHandler(
        LOG_FILE_NAME, maxBytes=LOG_FILE_MAX_SIZE, backupCount=LOG_FILE_BACKUP_COUNT
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)
    logger.debug("Debug mode enabled.")
    return root


def update_bucket(bucket_name, local_file, remote_file_name):
    """Update the s3 bucket with the new contents."""
    s3 = boto3.client("s3")
    s3.upload_file(local_file, bucket_name, remote_file_name)


def create_dummy_files(output_dir):
    """Create dummy files to test cleanup_old_files."""
    for n in range(1, 21):
        dummy_filename = "dummy_file_{!s}.gpg".format(n)
        full_path_dummy_filename = os.path.join(output_dir, dummy_filename)
        # Use open to create files.
        with open(full_path_dummy_filename, "w"):
            pass
        st = os.stat(full_path_dummy_filename)
        # Set file modification time to n days earlier than it was.
        # Note that there are 86400 seconds per day.
        os.utime(full_path_dummy_filename, (st.st_atime, st.st_mtime - (86400 * n)))


def cleanup_old_files(output_dir, file_retention_num_days):
    """Delete any *.gpg files older than file_retention_num_days in the specified output_dir."""
    now_unix = time.time()
    for filename in os.listdir(output_dir):
        # We only care about filenames that end with .gpg
        if filename.endswith(".gpg"):
            full_path_filename = os.path.join(output_dir, filename)
            # If file modification time is older than
            # file_retention_num_days.  Note that there are 86400
            # seconds per day.
            file_retention_in_secs = file_retention_num_days * 86400
            if os.stat(full_path_filename).st_mtime < now_unix - file_retention_in_secs:
                # Delete file locally
                os.remove(full_path_filename)


def cleanup_bucket_files(object_retention_days):
    """Delete oldest files if they are older than the provided retention time."""
    retention_time = flatten_datetime(
        datetime.now(tz.tzlocal()) - relativedelta(days=object_retention_days)
    )
    s3 = boto3.client("s3")
    response = None

    while True:
        if response is None:
            response = s3.list_objects_v2(Bucket=BUCKET_NAME, Prefix=SAVEFILE_PREFIX)
        elif response["IsTruncated"] is True:
            response = s3.list_objects_v2(
                Bucket=BUCKET_NAME,
                Prefix=SAVEFILE_PREFIX,
                ContinuationToken=response["NextContinuationToken"],
            )
        else:
            break

        del_list = [
            {"Key": o["Key"]}
            for o in response.get("Contents", [])
            if flatten_datetime(o["LastModified"]) < retention_time
        ]
        # AWS requires a list of objects and an empty list is seen as malformed.
        if len(del_list) > 0:
            del_resp = s3.delete_objects(
                Bucket=BUCKET_NAME, Delete={"Objects": del_list}
            )
            for err in del_resp.get("Errors", []):
                logger.error(
                    "Failed to delete '{}' :: {} - {}\n".format(
                        err["key"], err["Code"], err["Message"]
                    )
                )


def generate_cursor(collection, parameters):
    """Query collection and return a cursor to be used for data retrieval."""
    # We set no_cursor_timeout so that long retrievals do not cause generated
    # cursors to expire on the MongoDB server. This allows us to generate all cursors
    # up front and then pull results without worrying about a generated cursor
    # timing out on the server.
    return collection.find(
        parameters["query"], parameters["projection"], no_cursor_timeout=True
    )


def query_data(collection, cursor, tbz_file, tbz_filename, end_of_data_collection):
    """Query collection for data matching query and add it to tbz_file."""
    logger.info("Fetching from {} collection...".format(collection))

    json_filename = "{}_{!s}.json".format(
        collection,
        end_of_data_collection.isoformat().replace(":", "").split(".")[0],
    )

    # The previous method converted all documents retrieved into a JSON string at
    # once. This had a very large memory overhead and certain queries would
    # consume enough memory in this process to crash the AWS instance being used
    # before pagination was implemented. We are now retrieving and processing
    # a single document at a time and the memory overhead is drastically lower.
    with open(json_filename, "w") as collection_file:
        collection_file.write("[")

        for doc in cursor:
            collection_file.write(to_json([doc])[1:-2])
            collection_file.write(",")

        if cursor.retrieved != 0:
            # If we output documents then we have a trailing comma, so we need to
            # roll back the file location by one byte to overwrite as we finish
            collection_file.seek(-1, os.SEEK_END)

        collection_file.write("\n]")

    logger.info("Finished writing {} to file.".format(collection))
    tbz_file.add(json_filename)
    logger.info("Added {} to {}".format(json_filename, tbz_filename))
    # Delete file once added to tar
    if os.path.exists(json_filename):
        os.remove(json_filename)
        logger.info("Deleted {} as part of cleanup.".format(json_filename))


def main():
    """Retrieve data, aggreate into a compressed archive, and encrypt it to store or upload to S3."""
    global __doc__
    __doc__ = __doc__.replace("COMMAND_NAME", __file__)
    args = docopt(__doc__, version="v0.0.1")

    setup_logging(args["--debug"])

    logger.info("Beginning data extraction process.")

    if not (
        args["--cyhy-config"] or args["--scan-config"] or args["--assessment-config"]
    ):
        logger.error("At least one database configuration must be supplied.")
        sys.exit(1)

    if args["--cyhy-config"]:
        logger.debug("Creating connection to cyhy database.")
        cyhy_db = db_from_config(args["--cyhy-config"])
    if args["--scan-config"]:
        logger.debug("Creating connection to scan database.")
        scan_db = db_from_config(args["--scan-config"])
    if args["--assessment-config"]:
        logger.debug("Creating connection to assessment database.")
        assessment_db = db_from_config(args["--assessment-config"])
    now = datetime.now(tz.tzutc())

    # Read parameters in from config file
    config = SafeConfigParser()
    config.read([args["--config"]])
    ORGS_EXCLUDED = set(config.get("DEFAULT", "FED_ORGS_EXCLUDED").split(","))
    if ORGS_EXCLUDED == {""}:
        ORGS_EXCLUDED = set()
    GNUPG_HOME = config.get("DEFAULT", "GNUPG_HOME")
    RECIPIENTS = config.get("DEFAULT", "RECIPIENTS").split(",")
    SIGNER = config.get("DEFAULT", "SIGNER")
    SIGNER_PASSPHRASE = config.get("DEFAULT", "SIGNER_PASSPHRASE")
    OUTPUT_DIR = config.get("DEFAULT", "OUTPUT_DIR")
    # Files older than this are deleted by cleanup_old_files()
    FILE_RETENTION_NUM_DAYS = int(config.get("DEFAULT", "FILE_RETENTION_NUM_DAYS"))
    ES_REGION = config.get("DMARC", "ES_REGION")
    ES_URL = config.get("DMARC", "ES_URL")
    ES_RETRIEVE_SIZE = int(config.get("DMARC", "ES_RETRIEVE_SIZE"))
    ES_AWS_CONFIG_SECTION_NAME = config.get("DMARC", "ES_AWS_CONFIG_SECTION_NAME")

    # Check if OUTPUT_DIR exists; if not, bail out
    if not os.path.exists(OUTPUT_DIR):
        logger.error("Output directory '{}' does not exist.".format(OUTPUT_DIR))
        sys.exit(1)

    # Set up GPG (used for encrypting and signing)
    gpg = gnupg.GPG(
        gpgbinary="gpg2",
        gnupghome=GNUPG_HOME,
        verbose=args["--verbose"],
        options=["--pinentry-mode", "loopback", "-u", SIGNER],
    )
    gpg.encoding = "utf-8"

    if args["--date"]:
        # Note this date is in UTC timezone
        date_of_data = datetime.strptime(args["--date"], "%Y-%m-%d")
        end_of_data_collection = flatten_datetime(
            timezone("UTC").localize(date_of_data)
        )
    else:
        end_of_data_collection = flatten_datetime(now)

    start_of_data_collection = end_of_data_collection + relativedelta(days=-1)

    logger.debug(
        "Extracting data from {} to {}.".format(
            start_of_data_collection, end_of_data_collection
        )
    )

    # Create tar/bzip2 file for writing
    tbz_filename = "{}{!s}.tbz".format(
        SAVEFILE_PREFIX,
        end_of_data_collection.isoformat().replace(":", "").split(".")[0],
    )
    tbz_file = tarfile.open(tbz_filename, mode="w:bz2")

    if args["--cyhy-config"]:
        # Get a list of all non-retired orgs
        all_orgs = (
            cyhy_db["requests"]
            .find({"retired": {"$ne": True}}, {"_id": 1})
            .distinct("_id")
        )
        orgs = list(set(all_orgs) - ORGS_EXCLUDED)
    else:
        orgs = []

    default_projection = {"key": False}

    cyhy_collection = {
        "host_scans": {
            "query": {
                "owner": {"$in": orgs},
                "time": {
                    "$gte": start_of_data_collection,
                    "$lt": end_of_data_collection,
                },
            },
            "projection": default_projection,
        },
        "hosts": {
            "query": {
                "owner": {"$in": orgs},
                "last_change": {
                    "$gte": start_of_data_collection,
                    "$lt": end_of_data_collection,
                },
            },
            "projection": default_projection,
        },
        # The kevs collection does not have a field to indicate either
        # initial creation time or time of last modification. As a result we can
        # only pull the entire collection every time an extract is run.
        "kevs": {
            "query": {},
            "projection": default_projection,
        },
        "port_scans": {
            "query": {
                "owner": {"$in": orgs},
                "time": {
                    "$gte": start_of_data_collection,
                    "$lt": end_of_data_collection,
                },
            },
            "projection": default_projection,
        },
        # The requests collection does not have a field to indicate either
        # initial creation time or time of last modification. As a result we can
        # only pull the entire collection every time an extract is run.
        "requests": {
            "query": {},
            "projection": {
                "agency.acronym": True,
                "agency.location": True,
                "agency.name": True,
                "agency.type": True,
                "children": True,
                "networks": True,
                "report_types": True,
                "retired": True,
                "scan_types": True,
                "stakeholder": True,
            },
        },
        "tickets": {
            "query": {
                "owner": {"$in": orgs},
                "last_change": {
                    "$gte": start_of_data_collection,
                    "$lt": end_of_data_collection,
                },
            },
            "projection": default_projection,
        },
        "vuln_scans": {
            "query": {
                "owner": {"$in": orgs},
                "time": {
                    "$gte": start_of_data_collection,
                    "$lt": end_of_data_collection,
                },
            },
            "projection": default_projection,
        },
    }

    scan_collection = {
        "certs": {
            "query": {
                "sct_or_not_before": {
                    "$gte": start_of_data_collection,
                    "$lt": end_of_data_collection,
                }
            },
            "projection": default_projection,
        },
        "https_scan": {
            "query": {
                "scan_date": {
                    "$gte": start_of_data_collection,
                    "$lt": end_of_data_collection,
                }
            },
            "projection": default_projection,
        },
        "sslyze_scan": {
            "query": {
                "scan_date": {
                    "$gte": start_of_data_collection,
                    "$lt": end_of_data_collection,
                }
            },
            "projection": default_projection,
        },
        "trustymail": {
            "query": {
                "scan_date": {
                    "$gte": start_of_data_collection,
                    "$lt": end_of_data_collection,
                }
            },
            "projection": default_projection,
        },
    }

    # Neither collection in the assessment database have fields that indicate an
    # initial creation time or time of last modification. As a result we can only
    # pull the entire collection every time an extract is run.
    assessment_collection = {
        "assessments": {"query": {}, "projection": default_projection},
        "findings": {"query": {}, "projection": default_projection},
    }

    # Get cursors for the results of our queries. Create a tuple of the collection
    # name and the generated cursor to later iterate over for data retrieval. We
    # create cursors all at once to "lock in" the query results to reduce timing
    # issues for data retrieval.
    logger.info("Creating cursors for query results.")
    cursor_list = []
    if args["--cyhy-config"]:
        for collection in cyhy_collection:
            logger.debug("Generating cursor for {}.{}".format(cyhy_db.name, collection))
            cursor_list.append(
                (
                    cyhy_db[collection].name,
                    generate_cursor(cyhy_db[collection], cyhy_collection[collection]),
                )
            )
    if args["--scan-config"]:
        for collection in scan_collection:
            logger.debug("Generating cursor for {}.{}".format(scan_db.name, collection))
            cursor_list.append(
                (
                    scan_db[collection].name,
                    generate_cursor(scan_db[collection], scan_collection[collection]),
                )
            )
    if args["--assessment-config"]:
        for collection in assessment_collection:
            logger.debug(
                "Generating cursor for {}.{}".format(assessment_db.name, collection)
            )
            cursor_list.append(
                (
                    assessment_db[collection].name,
                    generate_cursor(
                        assessment_db[collection], assessment_collection[collection]
                    ),
                )
            )

    # Use our generated cursors to pull data now.
    logger.info("Extracting data from database(s).")
    for collection, cursor in cursor_list:
        query_data(
            collection,
            cursor,
            tbz_file,
            tbz_filename,
            end_of_data_collection,
        )
        # Just to be safe we manually close the cursor.
        cursor.close()

    # Note that we use the elasticsearch AWS profile here
    json_data = to_json(
        get_dmarc_data(
            ES_REGION,
            ES_URL,
            DAYS_OF_DMARC_REPORTS,
            ES_RETRIEVE_SIZE,
            ES_AWS_CONFIG_SECTION_NAME,
        )
    )
    json_filename = "DMARC_{!s}.json".format(
        end_of_data_collection.isoformat().replace(":", "").split(".")[0]
    )
    dmarc_file = open(json_filename, "w")
    dmarc_file.write(json_data)
    dmarc_file.close()
    tbz_file.add(json_filename)
    tbz_file.close()
    if os.path.exists(json_filename):
        os.remove(json_filename)
        logger.info("Deleted {} as part of cleanup.".format(json_filename))

    gpg_file_name = tbz_filename + ".gpg"
    gpg_full_path_filename = os.path.join(OUTPUT_DIR, gpg_file_name)
    # Encrypt (with public keys for all RECIPIENTS) and sign (with
    # SIGNER's private key)
    with open(tbz_filename, "rb") as f:
        status = gpg.encrypt_file(
            f,
            RECIPIENTS,
            armor=False,
            sign=SIGNER,
            passphrase=SIGNER_PASSPHRASE,
            output=gpg_full_path_filename,
        )

    if not status.ok:
        logger.error("GPG Error {} :: {}".format(status.status, status.stderr))
        sys.exit(1)

    logger.info(
        "Encrypted, signed, and compressed JSON data written to file: {}".format(
            gpg_full_path_filename
        )
    )

    if args["--aws"]:
        # send the contents to the s3 bucket
        update_bucket(BUCKET_NAME, gpg_full_path_filename, gpg_file_name)
        logger.info("Upload to AWS bucket complete")

    if os.path.exists(tbz_filename):
        os.remove(tbz_filename)
        logger.info("Deleted {} as part of cleanup.".format(tbz_filename))

    cleanup_old_files(OUTPUT_DIR, FILE_RETENTION_NUM_DAYS)

    if args["--cleanup-aws"]:
        cleanup_bucket_files(FILE_RETENTION_NUM_DAYS)

    logger.info("Finished data extraction process.")


if __name__ == "__main__":
    main()
