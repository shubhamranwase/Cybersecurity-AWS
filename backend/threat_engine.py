# ── Custom Threat Detection using FREE CloudTrail ───────────
import boto3
import json
import os
from datetime import datetime, timedelta

AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

SUSPICIOUS_EVENTS = [
    'DeleteTrail',
    'StopLogging',
    'DeleteBucket',
    'CreateAccessKey',
    'AttachUserPolicy',
    'PutBucketPublicAccessBlock',
    'AuthorizeSecurityGroupIngress',
    'DeleteSecurityGroup',
    'ModifyInstanceAttribute',
    'PutRolePolicy',
]

SEVERITY_MAP = {
    'DeleteTrail':                   9.0,
    'StopLogging':                   9.0,
    'CreateAccessKey':               8.0,
    'AttachUserPolicy':              8.0,
    'PutRolePolicy':                 7.5,
    'DeleteBucket':                  7.0,
    'AuthorizeSecurityGroupIngress': 6.5,
    'PutBucketPublicAccessBlock':    6.0,
    'DeleteSecurityGroup':           5.5,
    'ModifyInstanceAttribute':       5.0,
}

def scan_cloudtrail_threats():
    client = boto3.client('cloudtrail', region_name=AWS_REGION)
    threats = []

    for event_name in SUSPICIOUS_EVENTS:
        try:
            response = client.lookup_events(
                LookupAttributes=[
                    {'AttributeKey': 'EventName', 'AttributeValue': event_name}
                ],
                StartTime=datetime.now() - timedelta(hours=24),
                MaxResults=5
            )
            for e in response['Events']:
                ct_event = json.loads(e['CloudTrailEvent'])
                threats.append({
                    'id':          e['EventId'],
                    'title':       f"Suspicious: {e['EventName']}",
                    'severity':    SEVERITY_MAP.get(event_name, 5.0),
                    'type':        f"CloudTrail/{event_name}",
                    'region':      ct_event.get('awsRegion', AWS_REGION),
                    'updated_at':  str(e['EventTime']),
                    'status':      'ACTIVE',
                    'username':    e.get('Username', 'Unknown'),
                    'source_ip':   ct_event.get('sourceIPAddress', 'N/A'),
                })
        except Exception:
            continue

    return threats


def get_failed_logins():
    client = boto3.client('cloudtrail', region_name=AWS_REGION)
    failed = []
    try:
        response = client.lookup_events(
            LookupAttributes=[
                {'AttributeKey': 'EventName', 'AttributeValue': 'ConsoleLogin'}
            ],
            StartTime=datetime.now() - timedelta(hours=24),
            MaxResults=20
        )
        for e in response['Events']:
            ct_event = json.loads(e['CloudTrailEvent'])
            if ct_event.get('responseElements', {}).get('ConsoleLogin') == 'Failure':
                failed.append({
                    'id':         e['EventId'],
                    'title':      'Failed Console Login',
                    'severity':   6.0,
                    'type':       'CloudTrail/FailedLogin',
                    'region':     AWS_REGION,
                    'updated_at': str(e['EventTime']),
                    'status':     'ACTIVE',
                    'username':   e.get('Username', 'Unknown'),
                    'source_ip':  ct_event.get('sourceIPAddress', 'N/A'),
                })
    except Exception:
        pass
    return failed


def get_root_account_usage():
    client = boto3.client('cloudtrail', region_name=AWS_REGION)
    root_events = []
    try:
        response = client.lookup_events(
            LookupAttributes=[
                {'AttributeKey': 'Username', 'AttributeValue': 'root'}
            ],
            StartTime=datetime.now() - timedelta(hours=24),
            MaxResults=10
        )
        for e in response['Events']:
            ct_event = json.loads(e['CloudTrailEvent'])
            root_events.append({
                'id':         e['EventId'],
                'title':      f"Root Account Used: {e['EventName']}",
                'severity':   9.5,
                'type':       'CloudTrail/RootAccountUsage',
                    'region':     ct_event.get('awsRegion', AWS_REGION),
                'updated_at': str(e['EventTime']),
                'status':     'ACTIVE',
                'username':   'root',
                'source_ip':  ct_event.get('sourceIPAddress', 'N/A'),
            })
    except Exception:
        pass
    return root_events
