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
DYNAMODB = None
WAFREGIONAL = None
SECRETSMANAGER = None


def init() -> None:
    """Initialize global variables"""

    # Initialize logger
    global LOGGER  # pylint: disable-msg=W0603
    LOGGER = logging.getLogger()
    LOGGER.setLevel(logging.INFO)

    # Initialize boto3 dynamodb resource
    global DYNAMODB  # pylint: disable-msg=W0603
    try:
        DYNAMODB = boto3.resource('dynamodb').Table('foxsec-waf')
    except Exception as err:
        LOGGER.error('dynamodb resource failed to initialize: %s', err)
        sys.exit(1)

    # Initialize boto3 wafregional resource
    global WAFREGIONAL  # pylint: disable-msg=W0603
    try:
        WAFREGIONAL = boto3.client('waf-regional')
    except Exception as err:
        LOGGER.error('wafregional resource failed to initialize: %s', err)
        sys.exit(1)

    # Initialize boto3 secretsmanager resource
    global SECRETSMANAGER  # pylint: disable-msg=W0603
    try:
        SECRETSMANAGER = boto3.client('secretsmanager')
    except Exception as err:
        LOGGER.error('secretsmanager resource failed to initialize: %s', err)
        sys.exit(1)


def configure() -> dict:
    """Pull config from secrets manager"""

    try:
        secrets = SECRETSMANAGER.get_secret_value(
            SecretId='foxsec/dynamo_worker')
    except Exception as err:
        LOGGER.error('unable to get foxsec/dynamo_worker from secrets manager: %s', err)
        sys.exit(1)

    # Extract the JSON encoded secrets string
    config = secrets.get('SecretString')

    # Return a dict of json
    return json.loads(config)


def retry(retry_count=5, delay=5, allowed_exceptions=()):
    """Decorator that allows function retries"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None

            for _ in range(retry_count):
                try:
                    result = func(*args, **kwargs)
                    if result:
                        return result
                except allowed_exceptions as current_exception:
                    last_exception = current_exception
                # Instead of printing, consider using python logging module
                print('%s: Waiting for %s seconds before retrying again'
                      % (datetime.datetime.utcnow(), delay))
                time.sleep(delay)

            if last_exception is not None:
                raise type(last_exception) from last_exception
            return result
        return wrapper
    return decorator


def ip_address_validate(address: str) -> [str, str]:
    """Confirm valid IP and identify v4/v6"""
    ip_types = {4: 'IPV4', 6: 'IPV6'}

    try:
        ip_network = ipaddress.ip_network(address)
    except ValueError as err:
        print('ip_network failed: %s' % err)
        return err
    else:
        return str(ip_network), ip_types[ip_network.version]


def waf_mark_ipset_delete(source_address: str, source_type: str, waf_updates: dict) -> None:
    """
    Mark an address for deletion in waf_updates
    """

    waf_update = {
        'Action': 'DELETE',
        'IPSetDescriptor':
        {
            'Type': source_type,
            'Value': source_address
        }
    }

    if waf_update not in waf_updates:
        waf_updates.append(waf_update)


@retry(retry_count=5, delay=5)
def waf_update_ip_set(waf_ipset_id: str, waf_updates: dict) -> bool:
    """Update WAF ip set"""
    # Get our change token

    try:
        change_token = WAFREGIONAL.get_change_token()
    except ClientError as err:
        print('waf get_change_token failed: %s' % err)
        return False

    # ChangeTokenStatus, ResponseMetadata.RetryAttempts
    try:
        token_status = WAFREGIONAL.get_change_token_status(
            ChangeToken=change_token['ChangeToken'])
        print('TOKEN %s' % change_token['ChangeToken'])
        pprint(token_status)
    except ClientError as err:
        print('waf get_change_token_status failed: %s' % err)
        return False

    # Update our WAF ipset and return if successful
    try:
        WAFREGIONAL.update_ip_set(IPSetId=waf_ipset_id,
                                  ChangeToken=change_token['ChangeToken'],
                                  Updates=waf_updates)
    except ClientError as err:
        print('waf update_ip_set failed: %s' % err)
        return False

    return True


def dynamodb_delete_items(items: dict) -> None:
    """
    Remove item ids from dynamodb
    """

    print('Removing %d items from DynamoDB' % (len(items)))
    for item in items:
        try:
            DYNAMODB.delete_item(Key={'id': item})
        except ClientError as err:
            print('dynamodb delete_item failed: %s' % err)


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

    # Get items from DynamoDB
    dynamodb_items = DYNAMODB.scan(
        ProjectionExpression='id, address, expires_at, blocked_at, summary'
    )

    # Get ipset data from wafregional
    waf_ip_set = WAFREGIONAL.get_ip_set(IPSetId=config['ipset_id'])
    ipset_descriptors = waf_ip_set.get('IPSet').get('IPSetDescriptors')
    ip_networks = [ipset.get('Value') for ipset in ipset_descriptors]

    # Get current time
    current_time = datetime.datetime.utcnow()

    # Iteriate through DynamoDB
    for item in dynamodb_items.get('Items'):
        source_address, source_type = ip_address_validate(item.get('address'))
        summary = item.get('summary')
        expires_at = datetime.datetime.strptime(item.get('expires_at'),
                                                '%Y-%m-%d %H:%M:%S.%f')
        blocked_at = datetime.datetime.strptime(item.get('blocked_at'),
                                                '%Y-%m-%d %H:%M:%S.%f')

        if expires_at < current_time:
            # Limit how many Slack-notified rules we evaluate per run
            if slack_notifications >= 150:
                break

            # Limit how many DynamoDB items we need to delete per run
            if dynamodb_expired_addresses >= 500:
                break

            # Console log
            print('[Dynamo] Marking item %s, address %s for removal (expired %s)'
                  % (item.get('id'), source_address, expires_at))

            # Mark for deletion in DynamoDB
            dynamodb_pending_delete.append(item.get('id'))
            dynamodb_expired_addresses += 1

            # Delete from WAF if present
            if source_address in ip_networks:
                # Slack log
                slack_notifications += 1
                slack_log_expiration(source_address=source_address,
                                     expires_at=expires_at.strftime(
                                         '%Y-%m-%d %H:%M:%S'),
                                     blocked_at=blocked_at.strftime(
                                         '%Y-%m-%d %H:%M:%S'),
                                     summary=summary,
                                     slack_messages=slack_messages)

                # Mark for removal from waf ipset
                waf_mark_ipset_delete(source_address, source_type, waf_updates)

    # Iteriate through WAF ipset
    items = dynamodb_items.get('Items')
    for ip in ip_networks:  # pylint: disable-msg=C0103
        # Limit how many Slack-notified rules we evaluate per run
        if slack_notifications >= 150:
            break

        # Limit how many WAF updates per run
        if waf_rogue_addresses >= 150:
            break

        source_address, source_type = ip_address_validate(ip)
        if not list(filter(lambda item: item.get('address') == source_address, items)):
            # Console log
            print('[waf] Rogue ipset address %s marked for removal' %
                  source_address)

            # Slack log
            slack_notifications += 1
            slack_log_untracked(source_address=source_address,
                                slack_messages=slack_messages)

            # Mark for removal from waf ipset
            waf_mark_ipset_delete(source_address, source_type, waf_updates)
            waf_rogue_addresses += 1

    # Execute Dynamo updates
    if dynamodb_pending_delete:
        dynamodb_delete_items(dynamodb_pending_delete)

    # Execute WAF updates
    if waf_updates:
        if not waf_update_ip_set(config['ipset_id'], waf_updates):
            print('waf_update_ip_set failed')
            return False

    # Post to Slack
    post_slack_messages(slack_webhook_url=config['slack_webhook_url'],
                        slack_messages=slack_messages)

    print('Removed %d expired ipset entries, %d rogue WAF entries, and sent %d slack notifications'
          % (dynamodb_expired_addresses, waf_rogue_addresses, slack_notifications))
    return True


if __name__ == '__main__':
    main()
