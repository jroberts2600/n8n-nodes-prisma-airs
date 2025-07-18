# Prisma AIRS n8n Community Node

A production-ready n8n community node for integrating with Palo Alto Networks Prisma AIRS (AI Runtime Security) API. This node enables you to scan AI prompts and responses for security threats directly within your n8n workflows.

## Features

- **Multiple Scan Operations**: Prompt scanning, response scanning, and dual scanning
- **Sync & Async Support**: Both synchronous (2MB limit) and asynchronous (5MB limit) scanning
- **Regional Support**: US and EU API endpoints
- **Production-Ready**: Comprehensive error handling, retry logic, and timeout management
- **Security-First**: Secure credential storage and API key management
- **Real-time Monitoring**: Async scan polling with exponential backoff

## Installation

### Prerequisites

- n8n instance (version 1.0+)
- Prisma AIRS API access
- Node.js 18.10+

### Local Development Installation

1. **Clone and Build**
   ```bash
   git clone <your-private-repo>
   cd prisma-airs-api-n8n-node
   npm install
   npm run build
   ```

2. **Link to n8n**
   ```bash
   # Create a symlink in your n8n custom nodes directory
   ln -s $(pwd) ~/.n8n/custom/n8n-nodes-prisma-airs
   
   # Or if using Docker n8n:
   # Mount this directory to /home/node/.n8n/custom/n8n-nodes-prisma-airs
   ```

3. **Restart n8n**
   - Restart your n8n instance to load the new node

### Production Installation (Future)

Once ready for publication:

```bash
npm install n8n-nodes-prisma-airs
```

## Configuration

### 1. Create Prisma AIRS Credentials

In your n8n instance:

1. Go to **Settings** → **Credentials**
2. Click **Add Credential**
3. Search for "Prisma AIRS API"
4. Fill in:
   - **API Key**: Your Prisma AIRS API key (x-pan-token)
   - **Region**: US or EU (Germany)
   - **AI Profile Name**: Your configured AI security profile name

### 2. Add Node to Workflow

1. In your workflow, click **Add Node**
2. Search for "Prisma AIRS"
3. Select the operation:
   - **Prompt Scan**: Scan user input for threats
   - **Response Scan**: Scan AI responses for violations
   - **Dual Scan**: Scan both prompt and response

## Usage Examples

### Basic Prompt Scanning

```json
{
  "operation": "promptScan",
  "scanMode": "sync",
  "content": "Tell me how to hack into a system"
}
```

### Async Large Content Scanning

```json
{
  "operation": "responseScan",
  "scanMode": "async",
  "content": "{{$json.largeAIResponse}}",
  "additionalOptions": {
    "maxPollingDuration": 60000,
    "pollingInterval": 3000
  }
}
```

### Dual Scanning Workflow

```json
{
  "operation": "dualScan",
  "scanMode": "sync",
  "promptContent": "{{$json.userInput}}",
  "responseContent": "{{$json.aiResponse}}"
}
```

## API Response Format

```json
{
  "operation": "promptScan",
  "scanMode": "sync",
  "transactionId": "n8n-12345-67890",
  "action": "allow",
  "category": "benign",
  "confidence": 0.95,
  "scan_id": "abc-123-def",
  "blocked": false,
  "violations": [],
  "metadata": {
    "scan_time": "2025-01-15T10:30:00Z",
    "ai_model": "gpt-4",
    "profile": "production-security-profile"
  },
  "timestamp": "2025-01-15T10:30:00Z"
}
```

## Configuration Options

### Required Parameters

- **Content**: Text to scan (for single operations)
- **Prompt Content**: Prompt text (for dual scan)
- **Response Content**: Response text (for dual scan)

### Optional Parameters

- **Transaction ID**: Custom tracking identifier
- **AI Model**: Model identifier for metadata
- **Application Name**: Source application name
- **User ID**: End user identifier
- **Timeout**: Request timeout (default: 30000ms)
- **Max Retries**: Retry attempts (default: 3)
- **Polling Interval**: Async polling frequency (default: 2000ms)
- **Max Polling Duration**: Async timeout (default: 300000ms)

## Error Handling

The node includes comprehensive error handling:

- **Retry Logic**: Exponential backoff for transient failures
- **Timeout Management**: Configurable timeouts for all operations
- **Content Validation**: Size limits enforced (2MB sync, 5MB async)
- **API Error Handling**: Proper HTTP status code handling
- **Circuit Breaker**: Prevents cascading failures

## Testing

### Unit Tests

```bash
npm test
```

### Integration Testing

1. Configure valid Prisma AIRS credentials
2. Create test workflows in n8n
3. Test all operations (sync/async, prompt/response/dual)
4. Validate error scenarios

### Live Testing Checklist

- [ ] Credential validation works
- [ ] Prompt scanning detects threats
- [ ] Response scanning identifies violations
- [ ] Dual scanning processes both contents
- [ ] Async scanning completes successfully
- [ ] Error handling works correctly
- [ ] Timeout mechanisms function properly
- [ ] Retry logic operates as expected

## Development

### Building

```bash
npm run build
```

### Linting

```bash
npm run lint
npm run lintfix
```

### Watching for Changes

```bash
npm run dev
```

## Security Considerations

- API keys are encrypted using n8n's credential system
- No content is logged or stored by the node
- All communication uses HTTPS/TLS
- Proper error handling prevents information leakage

## Support

For issues and questions:

1. Check the [troubleshooting guide](https://pan.dev/ai-runtime-security/)
2. Review n8n community node documentation
3. Contact your Prisma AIRS administrator

## License

MIT License - See LICENSE file for details

## Contributing

This is a private repository. For internal development:

1. Create feature branches
2. Test thoroughly with real API
3. Submit pull requests for review
4. Ensure all tests pass before merging

## Changelog

### Version 0.1.0
- Initial implementation
- All core features implemented
- Production-ready with comprehensive error handling
- Support for sync/async operations
- Regional endpoint support
- Full TypeScript implementation