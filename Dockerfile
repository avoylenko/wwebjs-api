# Use the official Node.js Debian image as the base image
FROM node:18-bookworm-slim

# Set the working directory
WORKDIR /usr/src/app

# Install dependencies including curl & jq for healthcheck
ENV CHROME_BIN="/usr/bin/chromium" \
    PUPPETEER_SKIP_CHROMIUM_DOWNLOAD="true" \
    NODE_ENV="production"
RUN set -x \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       fonts-freefont-ttf \
       chromium \
       ffmpeg \
       curl \  
       jq \    
    && rm -rf /var/lib/apt/lists/*

# Copy package.json and package-lock.json to the working directory
COPY package*.json ./

# Install the dependencies
RUN npm ci --only=production --ignore-scripts

# Copy the rest of the source code to the working directory
COPY . .

# Expose the port the API will run on
EXPOSE 3000

# Start the API
CMD ["npm", "start"]