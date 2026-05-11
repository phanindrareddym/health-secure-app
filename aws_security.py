import boto3
import json
import time
from datetime import datetime
import os

LOG_GROUP = "/healthsecure/security-events"
LOG_STREAM = "app-events"

def send_security_event(event_type, user_id, username, ip, location, device, provider, risk_score=0):
    # Create boto3 client INSIDE the function so .env is already loaded
    client = boto3.client(
        "logs",
        region_name=os.getenv("AWS_REGION")  # force region
    )

    event = {
        "event_type": event_type,
        "user_id": user_id,
        "username": username,
        "ip": ip,
        "location": location,
        "device_fingerprint": device,
        "provider": provider,
        "timestamp": datetime.utcnow().isoformat(),
        "risk_score": risk_score
    }

    log_event = {
        "timestamp": int(time.time() * 1000),
        "message": json.dumps(event)
    }

    try:
        client.put_log_events(
            logGroupName=LOG_GROUP,
            logStreamName=LOG_STREAM,
            logEvents=[log_event]
        )

    except client.exceptions.ResourceNotFoundException:
        client.create_log_stream(
            logGroupName=LOG_GROUP,
            logStreamName=LOG_STREAM
        )

        client.put_log_events(
            logGroupName=LOG_GROUP,
            logStreamName=LOG_STREAM,
            logEvents=[log_event]
        )
