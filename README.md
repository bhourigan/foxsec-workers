Foxsec pipeline workers

#### foxsec_sqs_worker.py
This worker is designed to be attached to a SQS queue as a Lambda worker,
invoked when messages are received in the queue.

Message body is a JSON payload containing details about the fraud detection
event generated by foxsec pipeline. This worker will extract the source
address and generate a WAF ipset entry for `source_address`.

The WAF API doesn't allow metadata to be stored along with ipset entries
so data is duplicated and stored in a DymamoDB database. The DynamoDB
worker is responsible for scanning items and triggering WAF ipset cleanup
actions.

Example message body:
```json
{
  "severity": "info",
  "id": "F1510555-C852-4051-A749-8E5125ECCB43",
  "summary": "website.com httprequest threshold_analysis N.N.N.N 201",
  "category": "httprequest",
  "timestamp": "2019-04-30T23:00:34.477Z",
  "metadata": [
    {
      "key": "category",
      "value": "threshold_analysis"
    },
    {
      "key": "sourceaddress",
      "value": "N.N.N.N"
    },
    {
      "key": "mean",
      "value": "3.9707556117609863"
    },
    {
      "key": "count",
      "value": "201"
    },
    {
      "key": "threshold_modifier",
      "value": "50.0"
    },
    {
      "key": "notify_merge",
      "value": "threshold_analysis"
    },
    {
      "key": "window_timestamp",
      "value": "2019-04-30T22:58:59.999Z"
    },
    {
      "key": "monitored_resource",
      "value": "website.com"
    }
  ]
}
```

#### foxsec_dynamo_worker.py
This worker is designed to be ran periodically (approx every 5 min)
and scans the DynamoDB items created by the SQS worker to identify 
entries that have expired.

This worker also has the capability to post notifications to a Slack
webhook. The primary audience for these messages is support staff,
so sending to something like MozDef or another SIEM is likely not
appropriate.
