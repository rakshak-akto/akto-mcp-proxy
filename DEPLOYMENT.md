# Cloudflare Workers Deployment Guide

## Environment Variables Configuration

The following environment variables must be configured in your Cloudflare Worker/Container settings:

### Required Environment Variables

1. **MCP_LLM_API_KEY** (Required)
   - Description: API key for the MCP threat detection service
   - Example: `sk-proj-xxxxx`
   - How to set: Add in Cloudflare Dashboard → Workers & Pages → Your Worker → Settings → Variables

### Optional Environment Variables

2. **LIBONNX_RUNTIME_PATH** (Optional)
   - Description: Path to the ONNX Runtime library
   - Default: `/usr/local/lib/libonnxruntime.so`
   - Only override if using a custom ONNX Runtime location
   - Example: `/custom/path/libonnxruntime.so`

3. **DEBUG** (Optional)
   - Description: Enable verbose logging for troubleshooting
   - Values: `true` or `false`
   - Default: `false`
   - Set to `true` for detailed request/response logging
   - Example: `true`

## Cloudflare Workers Configuration

### Via wrangler.toml

Add environment variables to your `wrangler.toml`:

```toml
[env.production.vars]
MCP_LLM_API_KEY = "your-api-key-here"
# Optional - uncomment and modify if needed:
# LIBONNX_RUNTIME_PATH = "/usr/local/lib/libonnxruntime.so"
# DEBUG = "false"

[env.production.workers_dev]
enabled = false

[env.production.placement]
mode = "container"

[[env.production.durable_objects.bindings]]
name = "CONTAINER_STATE"
class_name = "ContainerState"
```

### Via Cloudflare Dashboard

1. Navigate to Cloudflare Dashboard
2. Go to Workers & Pages
3. Select your worker
4. Click on Settings → Variables
5. Add the required environment variable:
   - Click "Add variable"
   - Variable name: `MCP_LLM_API_KEY`
   - Value: Your API key
   - Click "Save"

6. (Optional) Add optional environment variables if needed:
   - `LIBONNX_RUNTIME_PATH`: Only if using custom path (default: `/usr/local/lib/libonnxruntime.so`)
   - `DEBUG`: Set to `true` for verbose logging (default: `false`)

### Via Wrangler CLI

```bash
# Set required secret
wrangler secret put MCP_LLM_API_KEY
# Enter your API key when prompted

# (Optional) Set environment variables in wrangler.toml or via CLI
# For DEBUG mode (if needed):
wrangler secret put DEBUG
# Enter "true" when prompted

# Deploy with environment variables
wrangler deploy --env production
```

## Resource Requirements

### Minimum Resources (Required)
- **Memory**: 1024 MiB (1GB)
- **vCPU**: 0.25
- **Disk**: 2000 MB

### Recommended Resources (Optimal)
- **Memory**: 1536 MiB (1.5GB)
- **vCPU**: 0.5
- **Disk**: 2000 MB

## Deployment Steps

1. Build the Docker image:
```bash
docker build -f Dockerfile -t akto-mcp-proxy:latest .
```

2. Tag the image for your registry:
```bash
docker tag akto-mcp-proxy:latest registry.example.com/akto-mcp-proxy:latest
```

3. Push to your registry:
```bash
docker push registry.example.com/akto-mcp-proxy:latest
```

4. Deploy to Cloudflare Workers:
```bash
wrangler deploy --compatibility-date 2024-01-01
```

## Testing the Deployment

### Health Check
```bash
curl https://your-worker.workers.dev/health
```

### Test with Safe Request
```bash
curl -X POST https://your-worker.workers.dev/proxy/https/httpbin.org/post \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'
```

### Verify Threat Protection
```bash
curl -X POST https://your-worker.workers.dev/proxy/https/example.com/api \
  -H "Content-Type: application/json" \
  -d '{"path": "../../../etc/passwd"}'
```

Expected response for malicious request:
```json
{
  "error": "Request blocked by security policy",
  "details": {
    "malicious": true,
    "confidence": 1.0,
    "action": "block",
    "timestamp": "2025-09-18T16:43:36Z"
  }
}
```

## Monitoring

Check logs in Cloudflare Dashboard:
- Workers & Pages → Your Worker → Logs
- Look for:
  - `MCP validator initialized successfully` - Successful startup
  - `BLOCKED: Malicious request` - Blocked threats
  - `ALLOWED: Request passed validation` - Allowed requests
  - `MONITORING: Suspicious request` - Monitored requests

## Troubleshooting

### MCP Validator Failed to Initialize
- Check `MCP_LLM_API_KEY` is set correctly
- Verify API key is valid
- Check memory allocation (needs at least 1GB)

### Container Keeps Restarting
- Increase memory to 1536 MiB
- Increase vCPU to 0.5
- Check logs for OOM (Out of Memory) errors

### Slow Response Times
- Increase vCPU allocation
- Enable caching if possible
- Check network latency to target servers