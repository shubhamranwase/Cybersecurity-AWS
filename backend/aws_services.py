import boto3
import json
from datetime import datetime, timedelta

# ── GuardDuty Findings ──────────────────────────────────────
def get_guardduty_findings():
    client = boto3.client('guardduty', region_name='us-east-1')
    detectors = client.list_detectors()['DetectorIds']
    if not detectors:
        return []
    detector_id = detectors[0]

    finding_ids = client.list_findings(
        DetectorId=detector_id,
        FindingCriteria={
            'Criterion': {'severity': {'Gte': 4}}
        }
    )['FindingIds']

    if not finding_ids:
        return []

    findings = client.get_findings(
        DetectorId=detector_id,
        FindingIds=finding_ids[:20]
    )['Findings']

    return [
        {
            'id': f['Id'],
            'title': f['Title'],
            'severity': f['Severity'],
            'type': f['Type'],
            'region': f['Region'],
            'updated_at': f['UpdatedAt'],
            'status': 'ACTIVE' if not f['Service']['Archived'] else 'ARCHIVED'
        }
        for f in findings
    ]


# ── CloudTrail Events ───────────────────────────────────────
def get_cloudtrail_events():
    client = boto3.client('cloudtrail', region_name='us-east-1')
    response = client.lookup_events(
        LookupAttributes=[
            {'AttributeKey': 'EventName', 'AttributeValue': 'ConsoleLogin'}
        ],
        MaxResults=20
    )
    return [
        {
            'event_name': e['EventName'],
            'username': e.get('Username', 'Unknown'),
            'event_time': str(e['EventTime']),
            'source_ip': json.loads(e['CloudTrailEvent'])
                         .get('sourceIPAddress', 'N/A'),
        }
        for e in response['Events']
    ]


# ── CloudWatch Logs ─────────────────────────────────────────
def get_cloudwatch_logs(log_group_name, minutes=30):
    client = boto3.client('logs', region_name='us-east-1')
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
                'timestamp': event['timestamp'],
                'message': event['message'],
                'log_stream': event['logStreamName']
            }
            for event in response['events']
        ]
    except Exception as e:
        return [{'error': str(e)}]


# ── Security Hub Findings ───────────────────────────────────
def get_security_hub_findings():
    client = boto3.client('securityhub', region_name='us-east-1')
    response = client.get_findings(
        Filters={
            'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'}],
            'RecordState':    [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
        },
        MaxResults=20
    )
    return [
        {
            'id': f['Id'],
            'title': f['Title'],
            'severity': f['Severity']['Label'],
            'product': f['ProductName'],
            'description': f['Description'][:100] + '...'
        }
        for f in response['Findings']
    ]


# ── SNS Alert ───────────────────────────────────────────────
def send_sns_alert(topic_arn, subject, message):
    client = boto3.client('sns', region_name='us-east-1')
    response = client.publish(
        TopicArn=topic_arn,
        Subject=subject,
        Message=message
    )
    return response['MessageId']