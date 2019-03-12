# standard python libraries
from datetime import datetime, timedelta
import logging
import re

# third-party libraries
import boto3
import requests
from requests_aws4auth import AWS4Auth


DEFAULT_ES_RETRIEVE_SIZE = 10000


def query_elasticsearch(session, es_region, es_url, since,
                        es_retrieve_size=DEFAULT_ES_RETRIEVE_SIZE):
    """Query Elasticsearch for all DMARC aggregate reports received
    since a given time.

    Parameters
    ----------
    session : boto3.session.Session
    The boto3 session.

    es_region : str
    The AWS region in which the DMARC Elasticsearch database resides.

    es_url : str
    The URL for the AWS DMARC Elasticsearch database.

    since : datetime
    All DMARC aggregate reports since this time will be returned.

    es_retrieve_size : int
    The number of records to retrieve from Elasticsearch per request.

    Returns
    -------
    list : a list of all DMARC aggregate reports received in the past
    seven days

    Throws
    ------
    requests.exceptions.RequestException: If an error is returned
    by Elasticsearch.
    """
    ans = None

    # Construct the auth from the AWS credentials
    aws_credentials = session.get_credentials()
    awsauth = AWS4Auth(aws_credentials.access_key,
                       aws_credentials.secret_key,
                       es_region, 'es',
                       session_token=aws_credentials.token)
    # Now construct the query.
    query = {
        'size': es_retrieve_size,
        'query': {
            'constant_score': {
                'filter': {
                    'bool': {
                        'must': [
                            {
                                'range': {
                                    'report_metadata.date_range.begin': {
                                        'gte': (since - datetime(1970, 1, 1)).total_seconds()
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        }
    }

    # Now perform the query.  We have to do a little finagling with
    # the scroll API in order to get past the 10000 document limit.
    # (I verified that we do run into that limit on occasion.)
    scroll_again = True
    scroll_id = None
    logging.debug('Querying Elasticsearch database')
    response = requests.get('{}/_search?scroll=1m'.format(es_url),
                            auth=awsauth,
                            json=query,
                            headers={'Content-Type': 'application/json'},
                            timeout=300)
    # Raises an exception if we didn't get back a 200 code
    response.raise_for_status()

    hits = response.json()['hits']['hits']
    scroll_id = response.json()['_scroll_id']
    ans = hits

    # If there were fewer hits than es_retrieve_size then there is no
    # need to keep scrolling
    if len(hits) < es_retrieve_size:
        scroll_again = False

    es_url_no_index = re.sub('/[^/]*$', '', es_url)
    while scroll_again:
        scroll_json = {
            'scroll': '1m',
            'scroll_id': scroll_id
        }
        logging.debug('Requesting another page of results from Elasticsearch')
        response = requests.get('{}/_search/scroll'.format(es_url_no_index),
                                auth=awsauth,
                                json=scroll_json,
                                headers={'Content-Type': 'application/json'},
                                timeout=300)
        # Raises an exception if we didn't get back a 200 code
        response.raise_for_status()

        hits = response.json()['hits']['hits']
        ans.extend(hits)

        # If there were fewer hits than es_retrieve_size then
        # there is no need to keep scrolling
        if len(hits) < es_retrieve_size:
            scroll_again = False

    return ans


def get_dmarc_data(es_region, es_url, days,
                   es_retrieve_size=DEFAULT_ES_RETRIEVE_SIZE,
                   aws_profile="default"):
    """Query Elasticsearch for all DMARC aggregate reports received
    since a given time.

    Parameters
    ----------
    es_region : str
    The AWS region in which the DMARC Elasticsearch database resides.

    es_url : str
    The URL for the AWS DMARC Elasticsearch database.

    days : int
    All DMARC aggregate reports since this many days ago will be
    returned.

    es_retrieve_size : int
    The number of records to retrieve from Elasticsearch per request.

    aws_profile : str
    The name of the AWS profile to use.

    Returns
    -------
    dict : a dict consisting of data for all DMARC aggregate reports
    received in the specified time frame

    Throws
    ------
    requests.exceptions.RequestException: If an error is returned
    by Elasticsearch.
    """
    since = datetime.utcnow() - timedelta(days=days)

    logging.info('Creating AWS session')
    session = boto3.Session(profile_name=aws_profile)

    logging.info('Retrieving DMARC data')
    reports = query_elasticsearch(session, es_region, es_url, since,
                                  es_retrieve_size)

    return reports
