"""FoxSec Dynamo worker"""
import datetime
import functools
import time
import ipaddress
import re
import logging
import sys
import json
from pprint import pprint
from botocore.exceptions import ClientError
import boto3
import requests


# Globals
LOGGER = None
SECRETSMANAGER = None
SQS = None

def init() -> None:
    """Initialize global variables"""

    # Initialize logger
    global LOGGER  # pylint: disable-msg=W0603
    LOGGER = logging.getLogger()
    LOGGER.setLevel(logging.INFO)

    # Initialize boto3 secretsmanager client
    global SECRETSMANAGER  # pylint: disable-msg=W0603
    try:
        SECRETSMANAGER = boto3.client('secretsmanager')
    except Exception as err:
        LOGGER.error('secretsmanager client failed to initialize: %s', err)
        sys.exit(1)

    # Initialize boto3 secretsmanager client
    global SQS  # pylint: disable-msg=W0603
    try:
        SQS = boto3.client('sqs')
    except Exception as err:
        LOGGER.error('sqs client failed to initialize: %s', err)
        sys.exit(1)


def configure() -> dict:
    """Pull config from secrets manager"""

    try:
        secrets = SECRETSMANAGER.get_secret_value(
            SecretId='foxsec/slack_sqs_worker')
    except Exception as err:
        LOGGER.error('unable to get foxsec/slack_sqs_worker from secrets manager: %s', err)
        sys.exit(1)

    # Extract the JSON encoded secrets string
    config = secrets.get('SecretString')

    # Return a dict of json
    return json.loads(config)


def slack_log_expiration(source_address: str, expires_at: str, blocked_at: str,
                         summary: str, slack_messages: dict) -> None:
    """
    Post a message to Slack when a WAF entry expires
    """

    search_pattern = source_address.split('/')[0]
    escaped_search_pattern = re.escape(search_pattern)
    slack_data = {
        'attachments': [{
            'fallback': 'WAF Blacklist entry removed for {}'.format(source_address),
            'color': '#36a64f',
            'pretext': 'WAF Blacklist entry removed',
            'fields': [{
                'title': 'Address',
                'value': source_address,
                'short': True,
            }, {
                'title': 'Blocked',
                'value': blocked_at,
                'short': True
            }, {
                'title': 'Expired',
                'value': expires_at,
                'short': True
            }, {
                'title': 'Summary',
                'value': summary
            }],
            'actions': [{
                'type': 'button',
                'text': 'View logs',
                'url': "https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#logs-insights:queryDetail=~(end~0~start~-3600~timeType~'RELATIVE~unit~'seconds~editorString~'fields*20*40message*20*7c*20filter*20*40message*20like*20*2f{}*2f*0a*7c*20sort*20*40timestamp*20desc*0a*7c*20limit*202000~isLiveTail~false~queryId~'webserver-prod*2fapache_access~source~'webserver-prod*2fapache_access)".format(escaped_search_pattern)
            }],
            'footer': 'foxsec_dynamo_worker'
        }]
    }

    # Queue message
    slack_messages.append(slack_data)


def slack_log_untracked(source_address: str, slack_messages: dict) -> None:
    """
    Post a message to Slack when a WAF entry is not tracked in Dynamo
    """

    slack_data = {
        'attachments': [{
            'fallback': 'Untracked WAF blacklist entry {} removed'.format(source_address),
            'color': '#ff004f',
            'pretext': 'Untracked WAF blacklist entry removed',
            'fields': [{
                'title': 'Address',
                'value': source_address,
                'short': False
            }],
            'footer': 'foxsec_dynamo_worker'
        }]
    }

    # Queue message
    slack_messages.append(slack_data)


def post_slack_messages(slack_webhook_url: str, slack_messages: dict) -> None:
    """
    Post a message to Slack
    """

    for slack_data in slack_messages:
        # Post the message to webhook
        response = requests.post(slack_webhook_url,
                                 json=slack_data,
                                 headers={'Content-Type': 'application/json'})

        # Slack docs say 1 message/s
        time.sleep(1)

        if response.status_code != 200:
            raise ValueError(
                'Request to slack returned an error %s, the response is:\n%s'
                % (response.status_code, response.text)
            )


def main() -> bool:
    """Main"""
    # Variables
    waf_updates = []
    waf_rogue_addresses = 0
    dynamodb_pending_delete = []
    dynamodb_expired_addresses = 0
    slack_notifications = 0
    slack_messages = []

    # Initialize
    init()

    # Get config from secrets manager
    config = configure()

    # Post to Slack
    post_slack_messages(slack_webhook_url=config['slack_webhook_url'],
                        slack_messages=slack_messages)

    print('Removed %d expired ipset entries, %d rogue WAF entries, and sent %d slack notifications'
          % (dynamodb_expired_addresses, waf_rogue_addresses, slack_notifications))
    return True


if __name__ == '__main__':
    main()
