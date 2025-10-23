# Prisma AIRS n8n Community Node

A production-ready n8n community node for integrating with Palo Alto Networks Prisma AIRS (AI Runtime Security) API. This node enables you to scan AI prompts and responses for security threats directly within your n8n workflows.

## Features

- **Multiple Scan Operations**: Prompt scanning, response scanning, dual scanning, batch scanning, and data masking
- **Batch Processing**: Scan up to 5 items in a single operation for efficiency
- **Data Masking**: Automatically detect and mask sensitive data in content
- **Contextual Grounding**: Validate AI responses against provided context (up to 100K characters)
- **Dynamic Profile Selection**: Override security profiles per scan using profile name or UUID
- **Sync & Async Support**: Both synchronous (2MB limit) and asynchronous (5MB limit) scanning
- **Regional Support**: US, EU (Germany), India, and Custom region endpoints
- **Attribution Metadata**: Automatic n8n workflow context (workflowId, workflowName, executionId, executionMode) 
- **Production-Ready**: Comprehensive error handling, retry logic, and timeout management
- **Security-First**: Secure credential storage and API key management
- **Real-time Monitoring**: Async scan polling with exponential backoff

## Installation

### Prerequisites

- n8n instance (version 1.0+)
- Prisma AIRS API access with valid API key
- Access to Strata Cloud Manager to configure AI security profiles

### For End Users

#### Option 1: Install via n8n Community Nodes (Recommended)
1. Open your n8n instance
2. Go to **Settings** → **Community Nodes**
3. Search for `prisma airs`
4. Click **Install**
5. Restart n8n

#### Option 2: Install via npm
```bash
npm install @paloaltonetworks/n8n-nodes-prisma-airs
```

### For Developers & Testing

#### Local Development Setup
1. **Clone and Build**
   ```bash
   git clone https://github.com/jroberts2600/n8n-nodes-prisma-airs.git
   cd n8n-nodes-prisma-airs
   npm install
   npm run build
   ```

2. **Link to n8n**
   ```bash
   # For local n8n installation
   ln -s $(pwd) ~/.n8n/custom/n8n-nodes-prisma-airs
   
   # For Docker n8n - add volume mount:
   # -v /path/to/n8n-nodes-prisma-airs:/home/node/.n8n/custom/n8n-nodes-prisma-airs
   ```

3. **Restart n8n**
   - Restart your n8n instance to load the new node

## Configuration

### 1. Create Prisma AIRS Credentials

In your n8n instance:

1. Go to **Settings** → **Credentials**
2. Click **Add Credential**
3. Search for "Prisma AIRS API"
4. Fill in:
   - **API Key**: Your Prisma AIRS API key (x-pan-token)
   - **Region**: US, EU (Germany), India, or Custom
   - **Custom Base URL**: (Only if Custom region selected) Your custom Prisma AIRS endpoint
   - **AI Profile Name**: Your configured AI security profile name (supports both names and UUIDs)

### 2. Add Node to Workflow

1. In your workflow, click **Add Node**
2. Search for "Prisma AIRS"
3. Select the operation:
   - **Prompt Scan**: Scan user input for threats
   - **Response Scan**: Scan AI responses for violations
   - **Dual Scan**: Scan both prompt and response with optional context
   - **Batch Scan**: Process multiple items (up to 5) in parallel
   - **Mask Data**: Scan and automatically mask sensitive data

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

### Dual Scanning with Context

```json
{
  "operation": "dualScan",
  "scanMode": "sync",
  "promptContent": "{{$json.userInput}}",
  "responseContent": "{{$json.aiResponse}}",
  "context": "{{$json.contextDocument}}"
}
```

### Batch Scanning Multiple Items

```json
{
  "operation": "batchScan",
  "scanMode": "async",
  "batchItems": {
    "items": [
      {
        "itemType": "prompt",
        "promptContent": "First prompt to scan"
      },
      {
        "itemType": "response",
        "responseContent": "AI generated response"
      },
      {
        "itemType": "both",
        "promptContent": "User question",
        "responseContent": "AI answer"
      }
    ]
  }
}
```

### Data Masking for Sensitive Content

```json
{
  "operation": "maskData",
  "scanMode": "sync",
  "maskContent": "My credit card is 4111-1111-1111-1111"
}
```

### Dynamic Profile Override

```json
{
  "operation": "promptScan",
  "scanMode": "sync",
  "content": "{{$json.userInput}}",
  "additionalOptions": {
    "aiProfileOverride": "strict-production-profile"
  }
}
```

Or using a profile UUID:

```json
{
  "operation": "promptScan",
  "scanMode": "sync",
  "content": "{{$json.userInput}}",
  "additionalOptions": {
    "aiProfileOverride": "03b32734-d06d-4bb7-a8df-ac5147630ce8"
  }
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
    "scan_time": "2025-10-21T10:30:00Z",
    "ai_model": "gpt-4",
    "profile": "production-security-profile"
  },
  "workflowId": "rKU3xnZb5S1ayJCG",
  "workflowName": "Customer Support Bot",
  "executionId": "385",
  "executionMode": "manual",
  "environment": "production",
  "timestamp": "2025-10-21T10:30:00Z"
}
```

### Attribution Metadata

The node automatically enriches all outputs with n8n workflow context for enhanced attribution and tracking:

- **workflowId**: Unique identifier for the workflow
- **workflowName**: Human-readable workflow name
- **executionId**: Unique ID for this specific execution
- **executionMode**: How the workflow was triggered (`manual`, `webhook`, `trigger`, `cli`)
- **environment**: Optional environment identifier (if configured)

This metadata is ideal for:
- **AI Gateway Integration**: Pass to upstream services 
- **Cost Attribution**: Track usage by workflow or execution
- **Audit Trails**: Correlate security scans with workflow runs
- **Multi-tenant Tracking**: Identify which workflows generated requests

## Configuration Options

### Required Parameters

- **Content**: Text to scan (for single operations)
- **Prompt Content**: Prompt text (for dual scan)
- **Response Content**: Response text (for dual scan)
- **Batch Items**: Array of items (for batch scan)
- **Mask Content**: Content to mask (for mask data operation)

### Optional Parameters

- **Context**: Grounding context for dual scan (up to 100K characters)
- **AI Profile Override**: Override default profile (name or UUID)
- **Transaction ID**: Custom tracking identifier
- **AI Model**: Model identifier for metadata (default: 'n8n-integration')
- **Application Name**: Source application name (default: 'n8n-workflow')
- **User ID**: End user identifier (default: 'n8n-user')
- **Environment**: Optional environment tag for output tracking (e.g., 'production', 'staging', 'development')
  - Note: This field is for workflow-level tracking only and appears in the output
  - The actual environment used by Prisma AIRS is configured in Strata Cloud Manager at the application level
- **Timeout**: Request timeout (default: 30000ms)
- **Max Retries**: Retry attempts (default: 3, max: 6)
- **Polling Interval**: Async polling frequency (default: 2000ms, min: 1000ms)
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

1. Check the [troubleshooting guide](https://pan.dev/prisma-airs/scan/api/)
2. Review n8n community node documentation
3. Contact your Prisma AIRS administrator

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create feature branches from `main`
3. Test thoroughly with real Prisma AIRS API
4. Submit pull requests for review
5. Ensure all tests and linting pass before merging

## Changelog

### Version 0.2.0
- **New**: Automatic attribution metadata (workflowId, workflowName, executionId, executionMode) in all outputs
- **New**: Custom region support for future Prisma AIRS deployments
- **New**: Optional environment tag field for workflow-level tracking in outputs
- **New**: India region support
- **Fixed**: Better handling of UUID vs profile name in credentials
- Fully backward compatible with v0.1.x

### Version 0.1.1
- Bug fixes and stability improvements

### Version 0.1.0
- Initial implementation
- All core features implemented
- Production-ready with comprehensive error handling
- Support for sync/async operations
- Regional endpoint support (US, EU)
- Full TypeScript implementation
