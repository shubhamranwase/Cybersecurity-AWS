import os

from flask import Flask, jsonify, request
from flask_cors import CORS

USE_REAL_AWS = os.getenv("USE_REAL_AWS", "false").lower() == "true"

if USE_REAL_AWS:
    from aws_services import (
        get_guardduty_findings,
        get_cloudwatch_logs,
        get_cloudtrail_events,
        send_sns_alert,
        get_security_hub_findings,
        get_cloudwatch_metrics,
        get_cloudwatch_alarms,
        get_threat_history,
        save_threat_to_dynamodb,
    )
else:
    from dummy_aws_services import (
        get_guardduty_findings,
        get_cloudwatch_logs,
        get_cloudtrail_events,
        send_sns_alert,
        get_security_hub_findings,
        get_cloudwatch_metrics,
        get_cloudwatch_alarms,
        get_threat_history,
    )

app = Flask(__name__)
CORS(app, origins=[
    "http://localhost:5173",
    "https://cybersecurity-aws.vercel.app/"
])

SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:security-alerts"


@app.route('/api/health',       methods=['GET'])
def health():
    return jsonify({'status': 'ok'})


@app.route('/api/guardduty',    methods=['GET'])
def guardduty():
    try:
        findings = get_guardduty_findings()
        return jsonify({'findings': findings, 'count': len(findings)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/cloudtrail',   methods=['GET'])
def cloudtrail():
    try:
        events = get_cloudtrail_events()
        return jsonify({'events': events})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/securityhub',  methods=['GET'])
def security_hub():
    try:
        findings = get_security_hub_findings()
        return jsonify({'findings': findings})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/metrics',      methods=['GET'])
def metrics():
    try:
        data = get_cloudwatch_metrics()
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/alarms',       methods=['GET'])
def alarms():
    try:
        data = get_cloudwatch_alarms()
        return jsonify({'alarms': data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/history',      methods=['GET'])
def history():
    try:
        data = get_threat_history()
        return jsonify({'history': data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/logs',         methods=['GET'])
def logs():
    log_group = request.args.get('group', '/aws/cloudtrail')
    minutes   = int(request.args.get('minutes', 30))
    try:
        data = get_cloudwatch_logs(log_group, minutes)
        return jsonify({'logs': data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/alert',        methods=['POST'])
def alert():
    data = request.json
    try:
        msg_id = send_sns_alert(
            SNS_TOPIC_ARN,
            data.get('subject', 'Security Alert'),
            data.get('message', 'Threat detected')
        )
        return jsonify({'message_id': msg_id, 'status': 'sent'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)
