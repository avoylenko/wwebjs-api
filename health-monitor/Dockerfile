FROM python:3.9-alpine

# Install required packages
RUN apk add --no-cache tzdata docker-cli

# Set Timezone
ENV TZ=Etc/UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Install Python dependencies
RUN pip install --no-cache-dir docker
RUN pip install --no-cache-dir pytz
# Copy the monitoring script
COPY monitor.py /usr/local/bin/monitor.py
RUN chmod +x /usr/local/bin/monitor.py

# Entrypoint
ENTRYPOINT ["python", "/usr/local/bin/monitor.py"]