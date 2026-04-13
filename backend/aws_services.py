import boto3
import json
import os
from datetime import datetime, timedelta
from threat_engine import scan_cloudtrail_threats, get_failed_logins, get_root_account_usage

AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")


# ── All Threats (Free) ──────────────────────────────────────
def get_guardduty_findings():
    threats      = scan_cloudtrail_threats()
    failed_logins = get_failed_logins()
    root_usage   = get_root_account_usage()
    all_findings = threats + failed_logins + root_usage

    # Sort by severity
    all_findings.sort(key=lambda x: x['severity'], reverse=True)
    return all_findings


# ── CloudTrail Login Events ─────────────────────────────────
def get_cloudtrail_events():
    client = boto3.client('cloudtrail', region_name=AWS_REGION)
    response = client.lookup_events(
        LookupAttributes=[
            {'AttributeKey': 'EventName', 'AttributeValue': 'ConsoleLogin'}
        ],
        MaxResults=20
    )
    return [
        {
            'event_name': e['EventName'],
            'username':   e.get('Username', 'Unknown'),
            'event_time': str(e['EventTime']),
            'source_ip':  json.loads(e['CloudTrailEvent'])
                          .get('sourceIPAddress', 'N/A'),
        }
        for e in response['Events']
    ]


# ── CloudWatch Metrics (Free) ───────────────────────────────
def get_cloudwatch_metrics():
    client = boto3.client('cloudwatch', region_name=AWS_REGION)
    end   = datetime.utcnow()
    start = end - timedelta(hours=24)

    def get_metric(namespace, metric_name, dimensions=[]):
        try:
            response = client.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=dimensions,
                StartTime=start,
                EndTime=end,
                Period=3600,
                Statistics=['Sum', 'Average']
            )
            points = sorted(response['Datapoints'], key=lambda x: x['Timestamp'])
            return [
                {
                    'time':  p['Timestamp'].strftime('%H:%M'),
                    'value': round(p.get('Sum', p.get('Average', 0)), 2)
                }
                for p in points
            ]
        except Exception:
            return []

    return {
        'api_calls':      get_metric('AWS/CloudTrail', 'EventCount'),
        'error_rate':     get_metric('AWS/CloudTrail', 'ErrorCount'),
        'login_attempts': get_metric('AWS/CloudTrail', 'EventCount',
                          [{'Name': 'EventName', 'Value': 'ConsoleLogin'}]),
    }


# ── IAM Access Analyzer (Free) ──────────────────────────────
def get_security_hub_findings():
    client = boto3.client('accessanalyzer', region_name=AWS_REGION)
    try:
        analyzers = client.list_analyzers()['analyzers']
        if not analyzers:
            return []

        analyzer_arn = analyzers[0]['arn']
        response = client.list_findings(
            analyzerArn=analyzer_arn,
            filter={'status': {'eq': ['ACTIVE']}}
        )
        return [
            {
                'id':            f['id'],
                'title':         f"Exposed: {f['resource']}",
                'severity':      f['severity'].upper(),
                'product':       'IAM Access Analyzer',
                'description':   f"Resource type: {f['resourceType']}"
            }
            for f in response['findings']
        ]
    except Exception as e:
        return [{'error': str(e)}]


# ── CloudWatch Alarms (Free) ────────────────────────────────
def get_cloudwatch_alarms():
    client = boto3.client('cloudwatch', region_name=AWS_REGION)
    try:
        response = client.describe_alarms(StateValue='ALARM')
        return [
            {
                'name':        a['AlarmName'],
                'state':       a['StateValue'],
                'description': a.get('AlarmDescription', 'No description'),
                'metric':      a['MetricName'],
                'updated_at':  str(a['StateUpdatedTimestamp'])
            }
            for a in response['MetricAlarms']
        ]
    except Exception:
        return []


# ── CloudWatch Logs (Free) ──────────────────────────────────
def get_cloudwatch_logs(log_group_name='/aws/cloudtrail', minutes=30):
    client = boto3.client('logs', region_name=AWS_REGION)
    end_time   = int(datetime.now().timestamp() * 1000)
    start_time = int((datetime.now() - timedelta(minutes=minutes)).timestamp() * 1000)
    try:
        response = client.filter_log_events(
            logGroupName=log_group_name,
            startTime=start_time,
            endTime=end_time,
            limit=50
        )
        return [
            {
                'timestamp':  event['timestamp'],
                'message':    event['message'],
                'log_stream': event['logStreamName']
            }
            for event in response['events']
        ]
    except Exception as e:
        return [{'error': str(e)}]


# ── SNS Alert (Free tier) ───────────────────────────────────
def send_sns_alert(topic_arn, subject, message):
    client = boto3.client('sns', region_name=AWS_REGION)
    response = client.publish(
        TopicArn=topic_arn,
        Subject=subject,
        Message=message
    )
    return response['MessageId']


# ── DynamoDB — Store Threat History (Free) ──────────────────
def save_threat_to_dynamodb(threat):
    client = boto3.resource('dynamodb', region_name=AWS_REGION)
    table  = client.Table('SecurityThreats')
    try:
        table.put_item(Item={
            'threat_id':  threat['id'],
            'title':      threat['title'],
            'severity':   str(threat['severity']),
            'type':       threat['type'],
            'status':     threat['status'],
            'timestamp':  str(datetime.now()),
        })
        return True
    except Exception:
        return False


def get_threat_history():
    client = boto3.resource('dynamodb', region_name=AWS_REGION)
    table  = client.Table('SecurityThreats')
    try:
        response = table.scan(Limit=50)
        return sorted(
            response['Items'],
            key=lambda x: x['timestamp'],
            reverse=True
        )
    except Exception:
        return []
