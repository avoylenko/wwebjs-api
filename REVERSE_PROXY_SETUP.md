# Reverse Proxy / Kong Setup Guide

This document provides configuration examples for deploying WWebJS API behind reverse proxies like Kong, Nginx, or other load balancers.

## Environment Variables

The following environment variables have been added to support reverse proxy deployments:

```bash
# Base path for mounting all routes (optional)
BASE_PATH=/api/v1/whatsapp

# Enable trust proxy for proper IP forwarding (required for reverse proxy)
TRUST_PROXY=true
```

## Kong Configuration

### Basic Kong Route Setup

```yaml
# Kong route configuration
routes:
  - name: wwebjs-api
    paths: ["/api/v1/whatsapp"]
    strip_path: true  # Important: removes the prefix before forwarding
    preserve_host: false
    protocols: ["http", "https"]
    service: wwebjs-service

services:
  - name: wwebjs-service
    url: http://wwebjs-api:3000
    connect_timeout: 60000
    write_timeout: 60000
    read_timeout: 60000
```

### Kong with WebSocket Support

```yaml
# Kong route for WebSocket connections
routes:
  - name: wwebjs-websocket
    paths: ["/api/v1/whatsapp/ws"]
    strip_path: true
    protocols: ["ws", "wss"]
    service: wwebjs-websocket-service

services:
  - name: wwebjs-websocket-service
    url: http://wwebjs-api:3000
```

## Nginx Configuration

```nginx
upstream wwebjs_backend {
    server wwebjs-api:3000;
}

server {
    listen 80;
    server_name api.yourdomain.com;

    location /api/v1/whatsapp/ {
        proxy_pass http://wwebjs_backend/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts for long-running operations
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

## Docker Compose with Reverse Proxy

```yaml
version: '3.8'

services:
  wwebjs-api:
    image: avoylenko/wwebjs-api:latest
    container_name: wwebjs-api
    restart: always
    environment:
      # Reverse proxy configuration
      - BASE_PATH=/api/v1/whatsapp
      - TRUST_PROXY=true
      
      # Other configurations
      - BASE_WEBHOOK_URL=https://api.yourdomain.com/api/v1/whatsapp/localCallbackExample
      - API_KEY=your_secure_api_key
      - ENABLE_LOCAL_CALLBACK_EXAMPLE=false
      - ENABLE_SWAGGER_ENDPOINT=true
    volumes:
      - ./sessions:/usr/src/app/sessions
    networks:
      - api-network

  nginx:
    image: nginx:alpine
    container_name: nginx-proxy
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - wwebjs-api
    networks:
      - api-network

networks:
  api-network:
    driver: bridge
```

## API Endpoint Examples

With `BASE_PATH=/api/v1/whatsapp` configured:

### Original endpoints:
- `GET /session/start/ABCD`
- `GET /client/getContacts/ABCD`
- `WebSocket: ws://localhost:3000/ws/ABCD`

### Behind reverse proxy:
- `GET https://api.yourdomain.com/api/v1/whatsapp/session/start/ABCD`
- `GET https://api.yourdomain.com/api/v1/whatsapp/client/getContacts/ABCD`
- `WebSocket: wss://api.yourdomain.com/api/v1/whatsapp/ws/ABCD`

## Important Notes

1. **Strip Path**: Always configure your reverse proxy to strip the base path before forwarding to the application
2. **Trust Proxy**: Set `TRUST_PROXY=true` to ensure proper IP detection for rate limiting
3. **WebSocket Headers**: Ensure `X-Forwarded-Host` header is properly forwarded for WebSocket connections
4. **Timeouts**: Configure appropriate timeouts for WhatsApp operations which can take time
5. **HTTPS**: Use HTTPS in production and update `BASE_WEBHOOK_URL` accordingly

## Troubleshooting

### Common Issues:

1. **404 Errors**: Check if `strip_path` is enabled in your reverse proxy
2. **WebSocket Connection Failed**: Ensure WebSocket upgrade headers are properly forwarded
3. **Rate Limiting Issues**: Verify `TRUST_PROXY=true` is set and `X-Forwarded-For` header is forwarded
4. **Webhook Callbacks**: Update `BASE_WEBHOOK_URL` to use the external domain with base path

### Testing:

```bash
# Test API endpoint
curl https://api.yourdomain.com/api/v1/whatsapp/ping

# Test WebSocket connection
wscat -c wss://api.yourdomain.com/api/v1/whatsapp/ws/test
```
