#!/usr/bin/env python3
import os
import time
import socket
import docker
import smtplib
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# --- Configuration from environment variables ---
TARGET_CONTAINER_NAME = os.environ.get('TARGET_CONTAINER_NAME', 'wwebjs_api')
CHECK_INTERVAL_SECONDS = int(os.environ.get('CHECK_INTERVAL_SECONDS', 60))
LOG_LINES = int(os.environ.get('LOG_LINES', 100))
EMAIL_TO = os.environ.get('EMAIL_TO')
EMAIL_FROM = os.environ.get('EMAIL_FROM', f'docker-monitor@{socket.gethostname()}')
EMAIL_SUBJECT_PREFIX = os.environ.get('EMAIL_SUBJECT_PREFIX', '[Docker Health Monitor]')

# --- SMTP Configuration ---
SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')
# Default to non-SSL connection to fix SSL version issue
SMTP_TLS = os.environ.get('SMTP_TLS', 'NO').upper() == 'YES'
SMTP_STARTTLS = os.environ.get('SMTP_STARTTLS', 'YES').upper() == 'YES'

# --- State File ---
STATE_FILE = f"/tmp/container_{TARGET_CONTAINER_NAME}_unhealthy.flag"

# --- HTML Templates ---
HTML_HEADER = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Docker Health Monitor</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 850px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background-color: #ff5252;
            color: white;
            padding: 15px;
            border-radius: 5px 5px 0 0;
            font-weight: bold;
        }
        .header.success {
            background-color: #4CAF50;
        }
        .content {
            padding: 20px;
            border: 1px solid #ddd;
            border-top: none;
            border-radius: 0 0 5px 5px;
        }
        .info-box {
            background-color: #f9f9f9;
            border-left: 4px solid #2196F3;
            padding: 10px 15px;
            margin: 15px 0;
        }
        .log-container {
            background-color: #f5f5f5;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            margin-top: 20px;
            overflow-x: auto;
        }
        .log-title {
            font-weight: bold;
            margin-bottom: 10px;
        }
        pre {
            margin: 0;
            white-space: pre-wrap;
            font-family: monospace;
            font-size: 13px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th, td {
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
    </style>
</head>
<body>
"""

HTML_FOOTER = """
</body>
</html>
"""

# Check required environment variables
if not EMAIL_TO:
    logger.error("ERROR: EMAIL_TO environment variable is required")
    exit(1)

def get_ist_timestamp():
    """Get current timestamp in IST timezone (UTC+5:30) without using pytz."""
    # Calculate IST offset (UTC+5:30)
    ist_offset = timedelta(hours=5, minutes=30)
    # Get current UTC time and add the offset
    utc_time = datetime.utcnow()
    ist_time = utc_time + ist_offset
    return ist_time.strftime("%Y-%m-%d %H:%M:%S IST")

def get_container_logs(container_id, tail=100):
    """Get the last N lines of container logs."""
    try:
        client = docker.from_env()
        container = client.containers.get(container_id)
        logs = container.logs(tail=tail).decode('utf-8', errors='replace')
        return logs
    except Exception as e:
        logger.error(f"Error retrieving container logs: {str(e)}")
        return f"Error retrieving logs: {str(e)}"

def get_container_info(container_id):
    """Get detailed information about the container."""
    try:
        client = docker.from_env()
        # Fix: Ensure container_id is properly validated
        if not container_id or not isinstance(container_id, str):
            return {"Error": "Invalid container ID"}

        container = client.containers.get(container_id)
        container_data = client.api.inspect_container(container.id)
        
        info = {
            "ID": container.id[:12],
            "Name": container.name,
            "Image": container.image.tags[0] if container.image.tags else container.image.id[:12],
            "Created": datetime.fromtimestamp(container_data['Created']).strftime('%Y-%m-%d %H:%M:%S'),
            "Status": container.status,
            "State": container_data['State']['Status'],
        }
        
        # Handle ports safely
        ports = container_data['NetworkSettings']['Ports']
        if ports:
            port_info = []
            for container_port, host_bindings in ports.items():
                if host_bindings:
                    for binding in host_bindings:
                        port_info.append(f"{binding.get('HostIp', '0.0.0.0')}:{binding.get('HostPort', '?')} → {container_port}")
                else:
                    port_info.append(f"{container_port} (not exposed)")
            info["Ports"] = port_info
        else:
            info["Ports"] = ["None"]
            
        # Handle mounts safely
        mounts = container_data.get('Mounts', [])
        if mounts:
            info["Mounts"] = [f"{m.get('Source', '?')} → {m.get('Destination', '?')}" for m in mounts]
        else:
            info["Mounts"] = ["None"]
            
        # Get restart policy
        restart_policy = container_data.get('HostConfig', {}).get('RestartPolicy', {}).get('Name', 'unknown')
        info["Restart Policy"] = restart_policy
        
        # Handle health checks safely
        if 'Health' in container_data.get('State', {}):
            health = container_data['State']['Health']
            info["Health Status"] = health.get('Status', 'unknown')
            
            failing_streak = health.get('FailingStreak')
            if failing_streak is not None:
                info["Failing Streak"] = failing_streak
                
            health_logs = health.get('Log', [])
            if health_logs and len(health_logs) > 0:
                last_check = health_logs[-1]
                if 'Output' in last_check:
                    info["Last Health Check"] = last_check['Output'].strip()
                
        return info
    except Exception as e:
        logger.error(f"Error retrieving container info: {str(e)}")
        return {"Error": str(e)}

def create_email_body_html(status, is_alert=True, container_info=None, logs=None):
    """Create an HTML email body with container status and logs if provided."""
    ist_timestamp = get_ist_timestamp()
    hostname = socket.gethostname()
    
    header_class = "header"
    if not is_alert:
        header_class += " success"
    
    status_title = f"{'🚨 ALERT' if is_alert else '✅ RECOVERY'}: Container '{TARGET_CONTAINER_NAME}' is {status}"
    
    html = HTML_HEADER
    html += f'<div class="{header_class}">{status_title}</div>'
    html += '<div class="content">'
    
    html += f'<p>The container <strong>{TARGET_CONTAINER_NAME}</strong> is reporting as <strong>{status}</strong>.</p>'
    
    # Add system information
    html += '<div class="info-box">'
    html += '<p><strong>System Information:</strong></p>'
    html += f'<p>Timestamp: {ist_timestamp}<br>'
    html += f'Monitor Host: {hostname}</p>'
    html += '</div>'
    
    # Add container details if available
    if container_info:
        html += '<h3>Container Details</h3>'
        html += '<table>'
        html += '<tr><th>Property</th><th>Value</th></tr>'
        
        for key, value in container_info.items():
            if key == "Mounts" and isinstance(value, list):
                html += f'<tr><td>{key}</td><td>{", ".join(str(v) for v in value[:3])}{"..." if len(value) > 3 else ""}</td></tr>'
            elif key == "Ports" and isinstance(value, list):
                html += f'<tr><td>{key}</td><td>{", ".join(str(v) for v in value[:3])}{"..." if len(value) > 3 else ""}</td></tr>'
            else:
                html += f'<tr><td>{key}</td><td>{value}</td></tr>'
        
        html += '</table>'
    
    # Add logs if provided and it's an alert
    if logs and is_alert:
        html += '<div class="log-container">'
        html += f'<div class="log-title">Last {LOG_LINES} Log Lines:</div>'
        html += f'<pre>{logs}</pre>'
        html += '</div>'
    
    html += '</div>'  # Close content div
    html += HTML_FOOTER
    
    return html

def create_email_body_text(status, is_alert=True, container_info=None, logs=None):
    """Create a plain text email body with container status and logs if provided."""
    ist_timestamp = get_ist_timestamp()
    hostname = socket.gethostname()
    
    body = []
    status_title = f"{'ALERT' if is_alert else 'RECOVERY'}: Container '{TARGET_CONTAINER_NAME}' is {status}"
    body.append(status_title)
    body.append("=" * len(status_title))
    body.append("")
    
    body.append(f"The container '{TARGET_CONTAINER_NAME}' is reporting as {status}.")
    body.append("")
    
    # Add system information
    body.append("SYSTEM INFORMATION:")
    body.append(f"Timestamp: {ist_timestamp}")
    body.append(f"Monitor Host: {hostname}")
    body.append("")
    
    # Add container details if available
    if container_info:
        body.append("CONTAINER DETAILS:")
        for key, value in container_info.items():
            if isinstance(value, list):
                body.append(f"{key}: {', '.join(str(v) for v in value[:3])}")
                if len(value) > 3:
                    body.append("  ...")
            else:
                body.append(f"{key}: {value}")
        body.append("")
    
    # Add logs if provided and it's an alert
    if logs and is_alert:
        body.append(f"LAST {LOG_LINES} LOG LINES:")
        body.append("-------------------")
        body.append(logs)
    
    return "\n".join(body)

def send_email(subject, status, is_alert=True, container_id=None):
    """Send an email notification with container status and logs."""
    container_info = None
    logs = None
    
    if container_id:
        container_info = get_container_info(container_id)
        if is_alert:  # Only include logs for alerts, not recovery
            logs = get_container_logs(container_id, tail=LOG_LINES)
    
    # Create message
    msg = MIMEMultipart("alternative")
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO
    msg['Subject'] = f"{EMAIL_SUBJECT_PREFIX} {subject}"
    
    # Plain text version
    text_body = create_email_body_text(status, is_alert, container_info, logs)
    msg.attach(MIMEText(text_body, 'plain'))
    
    # HTML version
    html_body = create_email_body_html(status, is_alert, container_info, logs)
    msg.attach(MIMEText(html_body, 'html'))
    
    # If there are logs and it's an alert, also attach them as a file
    if logs and is_alert:
        log_attachment = MIMEApplication(logs.encode('utf-8'), _subtype="text")
        log_attachment.add_header('Content-Disposition', 'attachment', 
                              filename=f"{TARGET_CONTAINER_NAME}_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        msg.attach(log_attachment)
    
    try:
        logger.info(f"Attempting to connect to SMTP server {SMTP_HOST}:{SMTP_PORT}")
        
        # Try to connect with insecure connection first (to debug SSL issue)
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30)
        
        # Log connection success
        logger.info("SMTP connection established")
        
        # Enable extended debug output
        server.set_debuglevel(1)
        
        # Use STARTTLS if configured
        if SMTP_STARTTLS:
            logger.info("Attempting STARTTLS")
            server.starttls()
        
        # Login if credentials provided
        if SMTP_USER and SMTP_PASS:
            logger.info(f"Logging in as {SMTP_USER}")
            server.login(SMTP_USER, SMTP_PASS)
        
        # Send email
        logger.info(f"Sending email to {EMAIL_TO}")
        server.send_message(msg)
        server.quit()
        
        logger.info(f"Sent email notification: {subject}")
        return True
    except Exception as e:
        logger.error(f"ERROR - Failed to send email notification to {EMAIL_TO}. Subject: {subject}. Error: {str(e)}")
        return False

def check_container_health():
    """Check the health status of the target container and return details."""
    try:
        client = docker.from_env()
        containers = client.containers.list(all=True, filters={"name": f"^/{TARGET_CONTAINER_NAME}$"})
        
        if not containers:
            return "not found", True, None
        
        container = containers[0]
        container_data = client.api.inspect_container(container.id)
        
        # Get state information
        state = container_data['State']
        is_running = state.get('Running', False)
        
        if not is_running:
            status = f"not running (exit code: {state.get('ExitCode', 'unknown')})"
            return status, True, container.id
        
        # Check for health information
        if 'Health' in state:
            health_status = state['Health']['Status']
            if health_status == 'healthy':
                return "healthy", False, container.id
            elif health_status == 'starting':
                return "starting", False, container.id
            elif health_status == 'unhealthy':
                return "unhealthy", True, container.id
            else:
                return f"in unknown health state ({health_status})", True, container.id
        else:
            return "running (no healthcheck defined)", False, container.id
            
    except Exception as e:
        logger.error(f"Error checking container health: {str(e)}")
        return f"error checking status: {str(e)}", True, None

def is_state_file_present():
    """Check if the state file exists, indicating a previous notification was sent."""
    return os.path.exists(STATE_FILE)

def create_state_file():
    """Create the state file to record that a notification has been sent."""
    try:
        with open(STATE_FILE, 'w') as f:
            f.write(datetime.now().isoformat())
    except Exception as e:
        logger.error(f"Error creating state file: {str(e)}")

def remove_state_file():
    """Remove the state file when container recovers."""
    try:
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)
    except Exception as e:
        logger.error(f"Error removing state file: {str(e)}")

def print_banner():
    """Print a banner with monitor information."""
    banner = f"""
{'='*70}
Docker Container Health Monitor
{'='*70}
🔍 Monitoring Container: {TARGET_CONTAINER_NAME}
⏱️  Check Interval:      {CHECK_INTERVAL_SECONDS} seconds
📧 Notifications To:    {EMAIL_TO}
📤 From Address:        {EMAIL_FROM}
💻 SMTP Server:         {SMTP_HOST}:{SMTP_PORT}
{'   '}SSL/TLS:           {'✅ Enabled' if SMTP_TLS else '❌ Disabled'}
{'   '}STARTTLS:          {'✅ Enabled' if SMTP_STARTTLS else '❌ Disabled'}
📋 Log Lines:           {LOG_LINES}
⏰ Current Time (IST):  {get_ist_timestamp()}
{'='*70}
    """
    print(banner)
    logger.info("Monitor started successfully")

def main():
    """Main monitoring loop."""
    print_banner()
    
    logger.info(f"Starting health monitoring for container '{TARGET_CONTAINER_NAME}'...")
    
    while True:
        current_state, is_unhealthy, container_id = check_container_health()
        
        if is_unhealthy:
            if not is_state_file_present():
                logger.info(f"Container '{TARGET_CONTAINER_NAME}' detected as {current_state}. Sending notification.")
                if send_email(
                    f"ALERT: Container '{TARGET_CONTAINER_NAME}' is {current_state}",
                    current_state,
                    is_alert=True,
                    container_id=container_id
                ):
                    create_state_file()
                else:
                    # Email failed, still create state file to prevent spam attempts
                    create_state_file()
                    logger.warning("Email sending failed, but marking state as notified to prevent spamming attempts.")
        else:
            # Container is not unhealthy
            if is_state_file_present():
                logger.info(f"Container '{TARGET_CONTAINER_NAME}' has recovered (current state: {current_state}). Sending recovery notification.")
                send_email(
                    f"RECOVERY: Container '{TARGET_CONTAINER_NAME}' is now {current_state}",
                    current_state,
                    is_alert=False,
                    container_id=container_id
                )
                # Remove the flag file regardless of email success
                remove_state_file()
        
        time.sleep(CHECK_INTERVAL_SECONDS)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Monitor stopped by user")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise