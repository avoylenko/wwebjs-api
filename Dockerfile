# Use the official Node.js Debian image as the base image
FROM node:22-bookworm-slim AS base

ENV CHROME_BIN="/usr/bin/chromium" \
    PUPPETEER_EXECUTABLE_PATH="/usr/bin/chromium" \
    PUPPETEER_SKIP_CHROMIUM_DOWNLOAD="true" \
    NODE_ENV="production"

WORKDIR /usr/src/app

FROM base AS deps

ARG USE_EDGE=false

COPY package*.json ./

RUN if [ "$USE_EDGE" = "true" ]; then \
      apt-get update && apt-get install -y --no-install-recommends git ca-certificates && \
      npm ci --only=production --ignore-scripts && \
      npm install --save-exact git+https://github.com/pedroslopez/whatsapp-web.js.git#main && \
      apt-get purge -y git ca-certificates && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*; \
    else \
      npm ci --only=production --ignore-scripts; \
    fi

# Create the final stage
FROM base

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    fonts-freefont-ttf \
    chromium \
    ffmpeg && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy only production dependencies from deps stage
COPY --from=deps /usr/src/app/node_modules ./node_modules
COPY --from=deps /usr/src/app/package*.json ./

# Copy application code
COPY server.js ./
COPY LICENSE ./
COPY swagger.json ./
COPY src/ ./src/

EXPOSE 3000

CMD ["npm", "start"]
