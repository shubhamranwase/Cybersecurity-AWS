# ── MOCK DATA (no AWS needed) ───────────────────────────────
# Replace these functions with real AWS calls later

def get_guardduty_findings():
    return [
        {
            'id': 'finding-001',
            'title': 'Unusual API call from unknown IP',
            'severity': 8.5,
            'type': 'UnauthorizedAccess:IAMUser',
            'region': 'us-east-1',
            'updated_at': '2026-03-18T10:30:00Z',
            'status': 'ACTIVE'
        },
        {
            'id': 'finding-002',
            'title': 'Brute force attack detected on EC2',
            'severity': 6.0,
            'type': 'Recon:EC2/PortProbeUnprotectedPort',
            'region': 'us-west-2',
            'updated_at': '2026-03-18T09:15:00Z',
            'status': 'ACTIVE'
        },
        {
            'id': 'finding-003',
            'title': 'Suspicious S3 bucket access',
            'severity': 3.0,
            'type': 'Policy:S3/BucketPublicAccessGranted',
            'region': 'eu-west-1',
            'updated_at': '2026-03-18T08:00:00Z',
            'status': 'ARCHIVED'
        },
        {
            'id': 'finding-004',
            'title': 'Cryptocurrency mining detected',
            'severity': 9.0,
            'type': 'CryptoCurrency:EC2/BitcoinTool',
            'region': 'us-east-1',
            'updated_at': '2026-03-18T07:45:00Z',
            'status': 'ACTIVE'
        },
    ]


def get_cloudtrail_events():
    return [
        {
            'event_name': 'ConsoleLogin',
            'username': 'admin',
            'event_time': '2026-03-18T10:00:00',
            'source_ip': '192.168.1.1'
        },
        {
            'event_name': 'ConsoleLogin',
            'username': 'dev-user',
            'event_time': '2026-03-18T09:30:00',
            'source_ip': '10.0.0.45'
        },
        {
            'event_name': 'ConsoleLogin',
            'username': 'unknown-user',
            'event_time': '2026-03-18T08:55:00',
            'source_ip': '203.0.113.99'
        },
        {
            'event_name': 'ConsoleLogin',
            'username': 'root',
            'event_time': '2026-03-18T08:20:00',
            'source_ip': '198.51.100.23'
        },
    ]


def get_cloudwatch_logs(log_group_name, minutes=30):
    return [
        {
            'timestamp': 1710756600000,
            'message': 'ERROR: Failed login attempt from 203.0.113.99',
            'log_stream': 'stream-001'
        },
        {
            'timestamp': 1710756500000,
            'message': 'WARNING: Unusual traffic spike detected',
            'log_stream': 'stream-002'
        },
    ]


def get_security_hub_findings():
    return [
        {
            'id': 'hub-001',
            'title': 'S3 bucket is publicly accessible',
            'severity': 'HIGH',
            'product': 'Security Hub',
            'description': 'An S3 bucket has been made public and may expose sensitive data...'
        },
        {
            'id': 'hub-002',
            'title': 'MFA not enabled for IAM user',
            'severity': 'MEDIUM',
            'product': 'Security Hub',
            'description': 'IAM user does not have MFA enabled, increasing risk of compromise...'
        },
    ]


def send_sns_alert(topic_arn, subject, message):
    # Mock — just returns a fake message ID
    print(f"[MOCK SNS] Subject: {subject} | Message: {message}")
    return "mock-message-id-12345"