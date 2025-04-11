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
import html # For escaping

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
EMAIL_TO_ENV = os.environ.get('EMAIL_TO') # Renamed to avoid conflict
EMAIL_FROM = os.environ.get('EMAIL_FROM', f'docker-monitor@{socket.gethostname()}')
EMAIL_SUBJECT_PREFIX = os.environ.get('EMAIL_SUBJECT_PREFIX', '[Docker Health Monitor]')

# --- Hardcoded Configuration ---
# <<< CHANGE THIS to your desired hardcoded email address, or set to None/empty string if not needed >>>
HARDCODED_RECIPIENT = "info@balkrushna.com"
#HARDCODED_RECIPIENT = None # Example if you don't want a hardcoded one

# --- SMTP Configuration ---
SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')
SMTP_TLS = os.environ.get('SMTP_TLS', 'NO').upper() == 'YES' # Implicit SSL (port 465 style)
SMTP_STARTTLS = os.environ.get('SMTP_STARTTLS', 'YES').upper() == 'YES' # Explicit TLS (port 587 style)

# --- State File ---
STATE_FILE = f"/tmp/container_{TARGET_CONTAINER_NAME}_unhealthy.flag"

# --- HTML Templates ---
# (HTML_HEADER and HTML_FOOTER remain the same)
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
            background-color: #ff5252; /* Red for alerts */
            color: white;
            padding: 15px;
            border-radius: 5px 5px 0 0;
            font-weight: bold;
        }
        .header.success {
            background-color: #4CAF50; /* Green for recovery */
        }
        .header.info {
             background-color: #2196F3; /* Blue for info/startup */
        }
        .content {
            padding: 20px;
            border: 1px solid #ddd;
            border-top: none;
            border-radius: 0 0 5px 5px;
        }
        .info-box {
            background-color: #f9f9f9;
            border-left: 4px solid #2196F3; /* Blue */
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
        ul {
             padding-left: 20px;
        }
    </style>
</head>
<body>
"""

HTML_FOOTER = """
</body>
</html>
"""

# --- Combine Recipients ---
all_recipients = set()
if EMAIL_TO_ENV:
    all_recipients.update(addr.strip() for addr in EMAIL_TO_ENV.split(',') if addr.strip() and '@' in addr.strip())
if HARDCODED_RECIPIENT and isinstance(HARDCODED_RECIPIENT, str) and HARDCODED_RECIPIENT.strip() and '@' in HARDCODED_RECIPIENT:
     all_recipients.add(HARDCODED_RECIPIENT.strip())
elif HARDCODED_RECIPIENT:
    logger.warning(f"Hardcoded recipient '{HARDCODED_RECIPIENT}' seems invalid or is empty. It will not be used.")

FINAL_RECIPIENT_LIST = list(all_recipients)
FINAL_RECIPIENT_STRING = ", ".join(sorted(FINAL_RECIPIENT_LIST)) # Sort for consistent display

# Check required environment variables (at least one recipient must be defined)
if not FINAL_RECIPIENT_LIST:
    logger.error("ERROR: No valid recipients defined. Set EMAIL_TO environment variable or configure HARDCODED_RECIPIENT in the script.")
    exit(1)

# Check if hardcoded recipient needs changing (only if it was intended to be used)
if HARDCODED_RECIPIENT == "your_fixed_email@example.com":
    logger.warning("WARNING: The HARDCODED_RECIPIENT is set to the default placeholder 'your_fixed_email@example.com'. Please update it in the script if you intend to use a hardcoded recipient.")

# --- Helper Functions ---

def hostname():
    """Get hostname safely."""
    try:
        return socket.gethostname()
    except Exception:
        logger.warning("Could not determine hostname.", exc_info=False)
        return "unknown-host"

def get_ist_timestamp():
    """Get current timestamp in IST timezone (UTC+5:30) without using pytz."""
    try:
        ist_offset = timedelta(hours=5, minutes=30)
        utc_time = datetime.utcnow()
        ist_time = utc_time + ist_offset
        return ist_time.strftime("%Y-%m-%d %H:%M:%S IST")
    except Exception as e:
        logger.error(f"Error generating IST timestamp: {e}")
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S Local") # Fallback

# --- Docker Interaction ---
# (get_container_logs, get_container_info, check_container_health remain mostly the same as the previous version)
# ... (Include the definitions for get_container_logs, get_container_info, check_container_health from the previous response here) ...
def get_container_logs(container_id, tail=100):
    """Get the last N lines of container logs."""
    try:
        client = docker.from_env()
        container = client.containers.get(container_id)
        logs = container.logs(tail=tail).decode('utf-8', errors='replace')
        return logs
    except docker.errors.NotFound:
        logger.error(f"Container with ID '{container_id}' not found when trying to get logs.")
        return "Error: Container not found."
    except Exception as e:
        logger.error(f"Error retrieving container logs for ID '{container_id}': {str(e)}")
        return f"Error retrieving logs: {str(e)}"

def get_container_info(container_id):
    """Get detailed information about the container."""
    try:
        client = docker.from_env()
        if not container_id or not isinstance(container_id, str):
             logger.warning(f"Invalid container ID provided to get_container_info: {container_id}")
             return {"Error": "Invalid container ID"}

        container = client.containers.get(container_id)
        container_data = client.api.inspect_container(container.id)

        created_str = container_data.get('Created')
        created_dt = "Unknown"
        if created_str:
             try:
                 created_dt = datetime.fromisoformat(created_str.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S UTC')
             except ValueError:
                 logger.warning(f"Could not parse container creation timestamp: {created_str}")

        info = {
            "ID": container.short_id,
            "Name": container.name,
            "Image": container.image.tags[0] if container.image.tags else container.image.short_id,
            "Created": created_dt,
            "Status": container.status,
            "State": container_data.get('State', {}).get('Status', 'unknown'),
        }

        ports = container_data.get('NetworkSettings', {}).get('Ports')
        if ports:
            port_info = []
            for container_port, host_bindings in ports.items():
                if host_bindings:
                    for binding in host_bindings:
                        port_info.append(f"{binding.get('HostIp', '0.0.0.0')}:{binding.get('HostPort', '?')} -> {container_port}")
                else:
                    port_info.append(f"{container_port} (not exposed)")
            info["Ports"] = port_info if port_info else ["None"]
        else:
            info["Ports"] = ["None"]

        mounts = container_data.get('Mounts', [])
        if mounts:
             info["Mounts"] = [f"{m.get('Source', '?')} -> {m.get('Destination', '?')}{' (ro)' if m.get('RW') is False else ''}" for m in mounts]
        else:
            info["Mounts"] = ["None"]

        restart_policy = container_data.get('HostConfig', {}).get('RestartPolicy', {}).get('Name', 'no')
        if restart_policy != 'no':
            max_retries = container_data.get('HostConfig', {}).get('RestartPolicy', {}).get('MaximumRetryCount', 0)
            if max_retries > 0:
                restart_policy += f" (max {max_retries} retries)"
        info["Restart Policy"] = restart_policy

        health_info = container_data.get('State', {}).get('Health')
        if health_info:
            info["Health Status"] = health_info.get('Status', 'unknown')
            failing_streak = health_info.get('FailingStreak')
            if failing_streak is not None:
                info["Failing Streak"] = failing_streak
            health_logs = health_info.get('Log', [])
            if health_logs:
                last_check = health_logs[-1]
                last_check_ts = "N/A"
                if 'Start' in last_check:
                     try:
                         last_check_ts = datetime.fromisoformat(last_check['Start'].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S UTC')
                     except ValueError: pass
                last_check_output = last_check.get('Output', '').strip()
                info["Last Health Check Time"] = last_check_ts
                if last_check_output:
                    info["Last Health Check Output"] = last_check_output[:200] + ('...' if len(last_check_output) > 200 else '')

        return info
    except docker.errors.NotFound:
        logger.error(f"Container with ID '{container_id}' not found when trying to get info.")
        return {"Error": f"Container with ID '{container_id}' not found."}
    except Exception as e:
        logger.error(f"Error retrieving container info for ID '{container_id}': {str(e)}")
        return {"Error": str(e)}

def check_container_health():
    """Check the health status of the target container and return details."""
    try:
        client = docker.from_env()
        containers = client.containers.list(all=True, filters={"name": f"^{TARGET_CONTAINER_NAME}$"})

        if not containers:
            logger.warning(f"Container '{TARGET_CONTAINER_NAME}' not found.")
            return "not found", True, None # Treat not found as unhealthy

        if len(containers) > 1:
             logger.warning(f"Multiple containers found matching name '{TARGET_CONTAINER_NAME}'. Using the first one found: {containers[0].name} ({containers[0].short_id})")

        container = containers[0]
        container_data = client.api.inspect_container(container.id)

        state = container_data.get('State', {})
        is_running = state.get('Running', False)
        status_desc = state.get('Status', 'unknown')

        if not is_running:
            exit_code = state.get('ExitCode', 'unknown')
            error_msg = state.get('Error', '')
            status_details = f"{status_desc}"
            if exit_code != 'unknown': status_details += f" (Exit Code: {exit_code})"
            if error_msg: status_details += f" Error: {error_msg}"
            logger.info(f"Container '{container.name}' is not running. Status: {status_details}")
            return status_details, True, container.id

        health_info = state.get('Health')
        if health_info:
            health_status = health_info.get('Status')
            if health_status == 'healthy':
                logger.debug(f"Container '{container.name}' is healthy.")
                return "healthy", False, container.id
            elif health_status == 'starting':
                 logger.info(f"Container '{container.name}' is starting (healthcheck pending).")
                 return "starting", False, container.id
            elif health_status == 'unhealthy':
                failing_streak = health_info.get('FailingStreak', 0)
                logger.warning(f"Container '{container.name}' is unhealthy (Failing Streak: {failing_streak}).")
                return f"unhealthy (streak: {failing_streak})", True, container.id
            else:
                logger.warning(f"Container '{container.name}' has an unknown health status: {health_status}. Treating as unhealthy.")
                return f"health:{health_status}", True, container.id
        else:
            logger.info(f"Container '{container.name}' is running (no healthcheck configured).")
            return "running (no healthcheck)", False, container.id

    except docker.errors.NotFound:
        logger.warning(f"Container '{TARGET_CONTAINER_NAME}' not found during health check.")
        return "not found", True, None
    except docker.errors.APIError as e:
        logger.error(f"Docker API error checking container health: {str(e)}")
        return f"docker API error: {str(e)}", True, None
    except Exception as e:
        logger.error(f"Unexpected error checking container health: {type(e).__name__} - {str(e)}")
        return f"error checking status: {str(e)}", True, None

# --- Email Generation ---
# (create_email_body_html, create_email_body_text remain the same as the previous version)
# ... (Include the definitions for create_email_body_html, create_email_body_text from the previous response here) ...
def create_email_body_html(status, is_alert=True, container_info=None, logs=None):
    """Create an HTML email body with container status and logs if provided."""
    ist_timestamp = get_ist_timestamp()
    host = hostname()

    header_class = "header"
    title_icon = ""
    if is_alert:
        title_icon = "🚨 ALERT"
    else:
        header_class += " success"
        title_icon = "✅ RECOVERY"

    status_title = f"{title_icon}: Container '{TARGET_CONTAINER_NAME}' is {status}"

    html_content = HTML_HEADER
    html_content += f'<div class="{header_class}">{status_title}</div>'
    html_content += '<div class="content">'
    html_content += f'<p>The container <strong>{TARGET_CONTAINER_NAME}</strong> on host <strong>{host}</strong> is reporting as <strong>{status}</strong>.</p>'

    html_content += '<div class="info-box">'
    html_content += '<p><strong>Event Information:</strong></p>'
    html_content += f'<p>Timestamp: {ist_timestamp}<br>'
    html_content += f'Monitor Host: {host}</p>'
    html_content += '</div>'

    if container_info:
        html_content += '<h3>Container Details</h3>'
        if "Error" in container_info:
             html_content += f'<p style="color: red;">Could not retrieve container details: {html.escape(container_info["Error"])}</p>'
        else:
             html_content += '<table><tr><th>Property</th><th>Value</th></tr>'
             for key, value in container_info.items():
                 display_value = "None"
                 if isinstance(value, list):
                     if value and value != ["None"]:
                         display_value = "<br>".join(html.escape(str(v)) for v in value[:3])
                         if len(value) > 3: display_value += "<br>..."
                 else:
                     display_value = html.escape(str(value))
                 html_content += f'<tr><td>{html.escape(key)}</td><td>{display_value}</td></tr>'
             html_content += '</table>'
    elif is_alert:
        html_content += '<p>Could not retrieve detailed container information.</p>'

    if logs and is_alert:
        safe_logs = html.escape(logs)
        html_content += '<div class="log-container">'
        html_content += f'<div class="log-title">Last {LOG_LINES} Log Lines:</div>'
        html_content += f'<pre>{safe_logs}</pre>'
        html_content += '</div>'
    elif is_alert and container_info and "Error" not in container_info:
         html_content += '<p>Could not retrieve container logs.</p>'

    html_content += '</div>'
    html_content += HTML_FOOTER
    return html_content

def create_email_body_text(status, is_alert=True, container_info=None, logs=None):
    """Create a plain text email body with container status and logs if provided."""
    ist_timestamp = get_ist_timestamp()
    host = hostname()

    body = []
    status_title = f"{'ALERT' if is_alert else 'RECOVERY'}: Container '{TARGET_CONTAINER_NAME}' is {status}"
    body.append(status_title)
    body.append("=" * len(status_title))
    body.append("")
    body.append(f"The container '{TARGET_CONTAINER_NAME}' on host '{host}' is reporting as {status}.")
    body.append("")

    body.append("EVENT INFORMATION:")
    body.append(f"- Timestamp: {ist_timestamp}")
    body.append(f"- Monitor Host: {host}")
    body.append("")

    if container_info:
        body.append("CONTAINER DETAILS:")
        if "Error" in container_info:
             body.append(f"  Could not retrieve container details: {container_info['Error']}")
        else:
            for key, value in container_info.items():
                display_value = "None"
                if isinstance(value, list):
                     if value and value != ["None"]:
                         display_value = ", ".join(str(v) for v in value[:3])
                         if len(value) > 3: display_value += ", ..."
                else:
                     display_value = str(value)
                body.append(f"- {key}: {display_value}")
        body.append("")
    elif is_alert:
        body.append("Could not retrieve detailed container information.")
        body.append("")

    if logs and is_alert:
        body.append(f"LAST {LOG_LINES} LOG LINES:")
        body.append("-" * 20)
        body.append(logs)
        body.append("-" * 20)
    elif is_alert and container_info and "Error" not in container_info:
         body.append("Could not retrieve container logs.")

    return "\n".join(body)

# --- SMTP Sending Logic ---

def _send_smtp_message(msg: MIMEMultipart):
    """Helper function to send a pre-constructed email message."""
    if not FINAL_RECIPIENT_LIST:
        logger.error("No recipients configured. Cannot send email.")
        return False

    # Extract subject for logging, default if not found
    subject = msg.get('Subject', '(No Subject)')
    # Extract recipient string for logging
    to_header = msg.get('To', FINAL_RECIPIENT_STRING) # Use string from header

    server = None
    try:
        logger.info(f"Attempting to connect to SMTP server {SMTP_HOST}:{SMTP_PORT}")
        if SMTP_TLS:
             logger.debug("Using SMTP_SSL (Implicit SSL/TLS)")
             server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30)
        else:
             logger.debug("Using SMTP (Explicit TLS/STARTTLS or plaintext)")
             server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30)

        # server.set_debuglevel(1) # Uncomment for detailed SMTP debugging

        if not SMTP_TLS and SMTP_STARTTLS:
            logger.info("Attempting STARTTLS")
            server.starttls()
            logger.info("STARTTLS successful")

        if SMTP_USER and SMTP_PASS:
            logger.info(f"Logging in as {SMTP_USER}")
            server.login(SMTP_USER, SMTP_PASS)
            logger.info("SMTP login successful")

        logger.info(f"Sending email '{subject}' to {to_header}")
        # Use FINAL_RECIPIENT_LIST for the actual delivery addresses
        server.send_message(msg, from_addr=EMAIL_FROM, to_addrs=FINAL_RECIPIENT_LIST)
        logger.info(f"Successfully sent email: {subject}")
        return True

    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"ERROR - SMTP Authentication failed for user {SMTP_USER}. Check credentials. Error: {e}")
    except smtplib.SMTPConnectError as e:
         logger.error(f"ERROR - Failed to connect to SMTP server {SMTP_HOST}:{SMTP_PORT}. Check host/port/firewall. Error: {e}")
    except smtplib.SMTPServerDisconnected as e:
         logger.error(f"ERROR - SMTP server disconnected unexpectedly. Error: {e}")
    except socket.timeout:
        logger.error(f"ERROR - Connection to SMTP server {SMTP_HOST}:{SMTP_PORT} timed out.")
    except socket.gaierror as e:
         logger.error(f"ERROR - Could not resolve SMTP host {SMTP_HOST}. Check DNS or hostname. Error: {e}")
    except Exception as e:
        logger.error(f"ERROR - Failed to send email notification to {to_header}. Subject: {subject}. Error: {type(e).__name__} - {str(e)}")
    finally:
        if server:
            try:
                server.quit()
            except Exception: pass # Ignore errors during quit
    return False

def send_email(subject, status, is_alert=True, container_id=None):
    """Send an alert or recovery email notification."""
    container_info = None
    logs = None

    if container_id:
        container_info = get_container_info(container_id)
        if is_alert and (container_info is None or "Error" not in container_info or container_info.get("ID")):
             logs = get_container_logs(container_id, tail=LOG_LINES)

    # Create message
    msg = MIMEMultipart("alternative")
    msg['From'] = EMAIL_FROM
    msg['To'] = FINAL_RECIPIENT_STRING
    msg['Subject'] = f"{EMAIL_SUBJECT_PREFIX} {subject}"
    msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')

    text_body = create_email_body_text(status, is_alert, container_info, logs)
    msg.attach(MIMEText(text_body, 'plain', 'utf-8'))

    html_body = create_email_body_html(status, is_alert, container_info, logs)
    msg.attach(MIMEText(html_body, 'html', 'utf-8'))

    if logs and is_alert:
        try:
            log_attachment = MIMEApplication(logs.encode('utf-8'), _subtype="plain")
            log_attachment.add_header('Content-Disposition', 'attachment',
                                  filename=f"{TARGET_CONTAINER_NAME}_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            msg.attach(log_attachment)
        except Exception as e:
            logger.error(f"Failed to create log attachment: {e}")

    # Use the helper function to send
    return _send_smtp_message(msg)

def send_startup_email():
    """Sends a notification when the monitor script starts."""
    logger.info("Attempting to send startup notification email.")
    host = hostname()
    ist_timestamp = get_ist_timestamp()
    subject = f"{EMAIL_SUBJECT_PREFIX} Monitor Started on {host}"

    # Create message
    msg = MIMEMultipart("alternative")
    msg['From'] = EMAIL_FROM
    msg['To'] = FINAL_RECIPIENT_STRING
    msg['Subject'] = subject
    msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')

    # --- Plain Text Body ---
    text_body_lines = [
        f"Docker Health Monitor - Startup Notification",
        f"============================================",
        f"The monitor script has started successfully.",
        "",
        f"MONITOR DETAILS:",
        f"- Monitoring Container: {TARGET_CONTAINER_NAME}",
        f"- Hostname:             {host}",
        f"- Check Interval:       {CHECK_INTERVAL_SECONDS} seconds",
        f"- Startup Time (IST):   {ist_timestamp}",
        "",
        f"NOTIFICATION RECIPIENTS:",
        f"Future alerts and recovery notices for '{TARGET_CONTAINER_NAME}' will be sent to:",
    ]
    # Add recipients line by line for clarity in text
    if FINAL_RECIPIENT_LIST:
         for recipient in sorted(FINAL_RECIPIENT_LIST):
              text_body_lines.append(f"- {recipient}")
    else:
         text_body_lines.append("- (None configured - this email should not have been sent!)") # Should not happen due to earlier check

    text_body = "\n".join(text_body_lines)
    msg.attach(MIMEText(text_body, 'plain', 'utf-8'))

    # --- HTML Body ---
    html_body = HTML_HEADER
    # Use 'info' class for the header color
    html_body += f'<div class="header info">ℹ️ Monitor Started: {html.escape(TARGET_CONTAINER_NAME)} on {html.escape(host)}</div>'
    html_body += '<div class="content">'
    html_body += f'<h2>Docker Health Monitor Startup</h2>'
    html_body += f'<p>The monitoring script for container <strong>{html.escape(TARGET_CONTAINER_NAME)}</strong> has started successfully on host <strong>{html.escape(host)}</strong>.</p>'

    html_body += '<div class="info-box">'
    html_body += '<p><strong>Monitor Configuration:</strong></p>'
    html_body += f'<p>Check Interval: {CHECK_INTERVAL_SECONDS} seconds<br>'
    html_body += f'Startup Time: {ist_timestamp}</p>'
    html_body += '</div>'

    html_body += '<h3>Notification Recipients</h3>'
    html_body += f'<p>Future alerts and recovery notices regarding the status of <strong>{html.escape(TARGET_CONTAINER_NAME)}</strong> will be sent to the following addresses:</p>'
    if FINAL_RECIPIENT_LIST:
        html_body += '<ul>'
        for recipient in sorted(FINAL_RECIPIENT_LIST):
            html_body += f'<li>{html.escape(recipient)}</li>'
        html_body += '</ul>'
    else:
         html_body += '<p style="color: red;">Error: No recipients were found!</p>' # Should not happen

    html_body += '</div>' # Close content div
    html_body += HTML_FOOTER
    msg.attach(MIMEText(html_body, 'html', 'utf-8'))

    # Use the helper function to send
    if _send_smtp_message(msg):
        logger.info(f"Startup notification email sent successfully to {FINAL_RECIPIENT_STRING}.")
    else:
        logger.error(f"Failed to send startup notification email to {FINAL_RECIPIENT_STRING}.")
    # Return value isn't strictly needed here, but could be used
    return True # Indicate attempt was made


# --- State File Management ---
# (is_state_file_present, create_state_file, remove_state_file remain the same)
# ... (Include the definitions for is_state_file_present, create_state_file, remove_state_file from the previous response here) ...
def is_state_file_present():
    """Check if the state file exists, indicating a previous notification was sent."""
    return os.path.exists(STATE_FILE)

def create_state_file():
    """Create the state file to record that a notification has been sent."""
    try:
        with open(STATE_FILE, 'w') as f:
            f.write(datetime.now().isoformat())
        logger.info(f"Created state file: {STATE_FILE}")
    except Exception as e:
        logger.error(f"Error creating state file {STATE_FILE}: {str(e)}")

def remove_state_file():
    """Remove the state file when container recovers."""
    try:
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)
            logger.info(f"Removed state file: {STATE_FILE}")
        else:
             logger.debug(f"State file {STATE_FILE} not found, nothing to remove.")
    except Exception as e:
        logger.error(f"Error removing state file {STATE_FILE}: {str(e)}")


# --- Banner & Main Loop ---

def print_banner():
    """Print a banner with monitor information."""
    recipients_display = FINAL_RECIPIENT_STRING if FINAL_RECIPIENT_STRING else "(None configured!)"
    host = hostname()
    banner = f"""
{'='*70}
Docker Container Health Monitor
{'='*70}
🚀 Hostname:            {host}
🔍 Monitoring Container: {TARGET_CONTAINER_NAME}
⏱️  Check Interval:      {CHECK_INTERVAL_SECONDS} seconds
📧 Notifications To:    {recipients_display}
📤 From Address:        {EMAIL_FROM}
💻 SMTP Server:         {SMTP_HOST}:{SMTP_PORT}
   Implicit SSL/TLS:  {'✅ Enabled (Port 465 style)' if SMTP_TLS else '❌ Disabled'}
   STARTTLS:          {'✅ Enabled (Port 587 style)' if SMTP_STARTTLS and not SMTP_TLS else '❌ Disabled (or N/A)'}
📋 Log Lines:           {LOG_LINES}
⏰ Current Time (IST):  {get_ist_timestamp()}
{'='*70}
    """
    print(banner)
    logger.info("Monitor starting up...")

def main():
    """Main monitoring loop."""
    print_banner()

    # <<< Send the initial startup email >>>
    send_startup_email()

    logger.info(f"Starting health monitoring loop for container '{TARGET_CONTAINER_NAME}'...")
    host = hostname() # Get hostname once for email subjects

    while True:
        logger.debug(f"Running health check for '{TARGET_CONTAINER_NAME}'...")
        current_state, is_unhealthy, container_id = check_container_health()
        logger.debug(f"Check result: State='{current_state}', Unhealthy={is_unhealthy}, ID='{container_id}'")

        was_previously_unhealthy = is_state_file_present()

        if is_unhealthy:
            if not was_previously_unhealthy:
                logger.warning(f"Container '{TARGET_CONTAINER_NAME}' detected as {current_state}. Sending alert notification.")
                email_subject = f"ALERT: [{host}] Container '{TARGET_CONTAINER_NAME}' is {current_state}"
                if send_email(
                    email_subject,
                    current_state,
                    is_alert=True,
                    container_id=container_id
                ):
                    create_state_file()
                else:
                    logger.error("Email sending failed for alert. Creating state file anyway to prevent repeated send attempts until recovery.")
                    create_state_file()
            else:
                 logger.info(f"Container '{TARGET_CONTAINER_NAME}' remains {current_state}. Already notified.")
        else:
            if was_previously_unhealthy:
                logger.info(f"Container '{TARGET_CONTAINER_NAME}' has recovered (current state: {current_state}). Sending recovery notification.")
                email_subject = f"RECOVERY: [{host}] Container '{TARGET_CONTAINER_NAME}' is now {current_state}"
                send_email(
                    email_subject,
                    current_state,
                    is_alert=False,
                    container_id=container_id
                )
                # Remove the flag file regardless of email success
                remove_state_file()
            else:
                 logger.debug(f"Container '{TARGET_CONTAINER_NAME}' is {current_state}. No alert was active.")

        logger.debug(f"Sleeping for {CHECK_INTERVAL_SECONDS} seconds...")
        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Monitor stopped by user (KeyboardInterrupt).")
    except Exception as e:
        logger.critical(f"CRITICAL UNEXPECTED ERROR in main loop: {type(e).__name__} - {str(e)}", exc_info=True)
    finally:
        logger.info("Monitor shutting down.")