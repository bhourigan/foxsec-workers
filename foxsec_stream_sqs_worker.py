"""FoxSec SQS worker"""
import os
import datetime
import functools
import time
import json
import ipaddress
import boto3
from botocore.exceptions import ClientError
from pprint import pprint

# Config
# region = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
WAF_IPSET_ID = os.environ.get('IPSET_ID')
WAF_IPSET_EXPIRATION_HOURS = os.environ.get('IPSET_EXPIRATION_HOURS', 24)

# Constants
DYNAMODB = boto3.resource('dynamodb').Table('foxsec-waf')
SQS = boto3.client('sqs')
WAFREGIONAL = boto3.client('waf-regional')


def parse_arn(arn):
    """Parse ARN"""

    elements = arn.split(':', 5)
    result = {
        'arn': elements[0],
        'partition': elements[1],
        'service': elements[2],
        'region': elements[3],
        'account': elements[4],
        'resource': elements[5],
        'resource_type': None
    }

    if '/' in result['resource']:
        result['resource_type'], result['resource'] = result['resource'].split('/', 1)
    elif ':' in result['resource']:
        result['resource_type'], result['resource'] = result['resource'].split(':', 1)

    return result


def sqs_delete_messages(arn, messages):
    """Delete messages from SQS arn"""
    # Parse SQS ARN
    arn = parse_arn(arn)

    # Get queue url from queue name
    try:
        queue_url = SQS.get_queue_url(QueueName=arn.get('resource'))
    except ClientError as err:
        print("sqs get_queue_url failed: %s" % err)
        return False

    # Delete received messages and return if successful
    try:
        SQS.delete_message_batch(QueueUrl=queue_url.get('QueueUrl'), Entries=messages)
    except ClientError as err:
        print("sqs delete_message_batch failed: %s" % err)
        return False

    return True


def lambda_handler(event, context):
    """Main entrypoint handler"""
    # Initialize
    del context  # Unused
    waf_updates = []
    sqs_entries = []
    dynamodb_items = []

    # Evaluate each record
    record = None
    for record in event.get('Records'):
        # Mark SQS message for deletion early
        sqs_entry = {
            'Id': record.get('messageId'),
            'ReceiptHandle': record.get('receiptHandle')
        }
        sqs_entries.append(sqs_entry)

        # Skip invalid records
        if not record.get('body'):
            print("Missing body")
            continue

        # Load JSON
        body = json.loads(record.get('body'))

        # Skip records without metadata
        if not body.get('metadata'):
            print("Missing metadata")
            continue

        # List of dict to dict
        metadata = {item['key']: item['value'] for item in body['metadata']}

        # Parse window_timestamp to datetime, calculate expires_at
        window_timestamp = datetime.datetime.strptime(metadata['window_timestamp'],
                                                      "%Y-%m-%dT%H:%M:%S.%fZ")
        expires_at = window_timestamp + datetime.timedelta(hours=int(WAF_IPSET_EXPIRATION_HOURS))

        # Validate source address
        try:
            source_address, source_type = ip_address_validate(metadata['sourceaddress'])
        except:  # pylint: disable-msg=W0702
            print("Invalid sourceaddress, continuing")
            continue

        # Sanity check
        if expires_at < datetime.datetime.utcnow():
            print("Expire date in the past, skipping %s" % (body['id']))
            continue

        # Put item in dynamodb put list
        dynamodb_item = {
            'id': body['id'],
            'summary': body['summary'],
            'address': source_address,
            'blocked_at': str(datetime.datetime.utcnow()),
            'expires_at': str(expires_at)
        }
        dynamodb_items.append(dynamodb_item)

        # Add update to waf updates
        waf_update = {
            'Action': 'INSERT',
            'IPSetDescriptor':
            {
                'Type': source_type,
                'Value': source_address
            }
        }
        waf_updates.append(waf_update)

    # Delete SQS messages
    if sqs_entries:
        print("SQS")
        pprint(sqs_entries)
        sqs_delete_messages(record.get('eventSourceARN'), sqs_entries)

    # Put items in DynamoDB
    if dynamodb_items:
        print("DYNAMODB")
        pprint(dynamodb_items)
        dynamodb_put_items(items=dynamodb_items)

    # Update WAF ip sets
    if waf_updates:
        print("WAF")
        pprint(waf_updates)
        waf_update_ip_set(WAF_IPSET_ID, waf_updates)
