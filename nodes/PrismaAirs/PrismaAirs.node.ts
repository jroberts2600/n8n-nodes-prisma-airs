import {
  IExecuteFunctions,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
  NodeOperationError,
  NodeApiError,
  IHttpRequestMethods,
  IDataObject,
  IHttpRequestOptions,
  ICredentialDataDecryptedObject,
  ApplicationError,
  NodeConnectionType,
} from 'n8n-workflow';

import { v4 as uuidv4 } from 'uuid';

interface PrismaAirsCredentials extends ICredentialDataDecryptedObject {
  apiKey: string;
  region: string;
  aiProfileName: string;
}

interface ScanContent {
  prompt?: string;
  response?: string;
}

interface ScanRequest {
  tr_id: string;
  ai_profile: {
    profile_name: string;
  };
  metadata: {
    app_user: string;
    ai_model: string;
    application_name: string;
  };
  contents: ScanContent[];
}

interface ScanResponse {
  action: 'allow' | 'block';
  category: string;
  confidence: number;
  scan_id: string;
  blocked: boolean;
  violations: string[];
  metadata: {
    scan_time: string;
    ai_model: string;
    profile: string;
  };
}

interface AsyncScanResponse {
  scan_id: string;
  report_id: string;
  status: 'queued' | 'processing' | 'completed' | 'failed';
  error?: string;
}

class PrismaAirsScanner {
  async executeSyncScan(
    context: IExecuteFunctions,
    baseUrl: string,
    scanRequest: ScanRequest,
    timeout: number,
    maxRetries: number
  ): Promise<ScanResponse> {
    const options: IHttpRequestOptions = {
      method: 'POST' as IHttpRequestMethods,
      url: `${baseUrl}/v1/scan/sync/request`,
      body: scanRequest,
      json: true,
      timeout,
      returnFullResponse: true,
    };

    return await this.executeWithRetry(context, options, maxRetries);
  }

  async executeAsyncScan(
    context: IExecuteFunctions,
    baseUrl: string,
    scanRequest: ScanRequest,
    timeout: number,
    maxRetries: number,
    pollingInterval: number,
    maxPollingDuration: number
  ): Promise<ScanResponse> {
    // Submit async scan
    const submitOptions: IHttpRequestOptions = {
      method: 'POST' as IHttpRequestMethods,
      url: `${baseUrl}/v1/scan/async/request`,
      body: scanRequest,
      json: true,
      timeout,
      returnFullResponse: true,
    };

    const asyncResponse = await this.executeWithRetry(context, submitOptions, maxRetries) as AsyncScanResponse;
    
    // Poll for results
    const startTime = Date.now();
    const resultsOptions: IHttpRequestOptions = {
      method: 'GET' as IHttpRequestMethods,
      url: `${baseUrl}/v1/scan/results/${asyncResponse.scan_id}`,
      json: true,
      timeout,
      returnFullResponse: true,
    };

    while (Date.now() - startTime < maxPollingDuration) {
      try {
        const result = await this.executeWithRetry(context, resultsOptions, maxRetries);
        
        if (result.status === 'completed') {
          return result as ScanResponse;
        } else if (result.status === 'failed') {
          throw new ApplicationError(`Async scan failed: ${result.error || 'Unknown error'}`);
        }
        
        // Wait before next poll
        await new Promise(resolve => setTimeout(resolve, pollingInterval));
      } catch (error) {
        if (error instanceof NodeApiError && error.httpCode === '404') {
          // Scan not ready yet, continue polling
          await new Promise(resolve => setTimeout(resolve, pollingInterval));
          continue;
        }
        throw error;
      }
    }

    throw new ApplicationError('Async scan timed out waiting for results');
  }

  private async executeWithRetry(
    context: IExecuteFunctions,
    options: IHttpRequestOptions,
    maxRetries: number
  ): Promise<any> {
    let lastError: Error | undefined;
    
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const response = await context.helpers.httpRequestWithAuthentication.call(context, 'prismaAirsApi', options);
        return response.body || response;
      } catch (error) {
        lastError = error as Error;
        
        if (error instanceof NodeApiError) {
          // Don't retry on client errors (4xx), only on server errors (5xx) or network issues
          if (error.httpCode && error.httpCode.startsWith('4')) {
            throw error;
          }
        }
        
        if (attempt < maxRetries) {
          // Exponential backoff: wait 2^attempt seconds
          const delay = Math.min(1000 * Math.pow(2, attempt), 30000);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }
    
    throw lastError || new ApplicationError('Request failed after retries');
  }
}

export class PrismaAirs implements INodeType {
  description: INodeTypeDescription = {
    displayName: 'Prisma AIRS',
    name: 'prismaAirs',
    icon: 'file:prisma-airs.svg',
    group: ['transform'],
    version: 1,
    subtitle: '={{$parameter["operation"] + ": " + $parameter["scanMode"]}}',
    description: 'Scan AI prompts and responses for security threats using Prisma AIRS',
    defaults: {
      name: 'Prisma AIRS',
    },
    inputs: [{ type: NodeConnectionType.Main }] as const,
    outputs: [{ type: NodeConnectionType.Main }] as const,
    credentials: [
      {
        name: 'prismaAirsApi',
        required: true,
      },
    ],
    properties: [
      {
        displayName: 'Operation',
        name: 'operation',
        type: 'options',
        noDataExpression: true,
        options: [
          {
            name: 'Prompt Scan',
            value: 'promptScan',
            description: 'Scan user input/prompts for security threats',
            action: 'Scan a prompt for security threats',
          },
          {
            name: 'Response Scan',
            value: 'responseScan',
            description: 'Scan AI-generated responses for policy violations',
            action: 'Scan a response for policy violations',
          },
          {
            name: 'Dual Scan',
            value: 'dualScan',
            description: 'Scan both prompt and response in sequence',
            action: 'Perform dual scanning of prompt and response',
          },
        ],
        default: 'promptScan',
      },
      {
        displayName: 'Scan Mode',
        name: 'scanMode',
        type: 'options',
        noDataExpression: true,
        options: [
          {
            name: 'Synchronous',
            value: 'sync',
            description: 'Immediate scan with results (2MB limit)',
          },
          {
            name: 'Asynchronous',
            value: 'async',
            description: 'Queued scan for larger content (5MB limit)',
          },
        ],
        default: 'sync',
      },
      {
        displayName: 'Content',
        name: 'content',
        type: 'string',
        typeOptions: {
          rows: 4,
        },
        default: '',
        required: true,
        description: 'The content to scan for security threats',
        displayOptions: {
          show: {
            operation: ['promptScan', 'responseScan'],
          },
        },
      },
      {
        displayName: 'Prompt Content',
        name: 'promptContent',
        type: 'string',
        typeOptions: {
          rows: 3,
        },
        default: '',
        required: true,
        description: 'The prompt content to scan',
        displayOptions: {
          show: {
            operation: ['dualScan'],
          },
        },
      },
      {
        displayName: 'Response Content',
        name: 'responseContent',
        type: 'string',
        typeOptions: {
          rows: 3,
        },
        default: '',
        required: true,
        description: 'The response content to scan',
        displayOptions: {
          show: {
            operation: ['dualScan'],
          },
        },
      },
      {
        displayName: 'Additional Options',
        name: 'additionalOptions',
        type: 'collection',
        placeholder: 'Add Option',
        default: {},
        options: [
          {
            displayName: 'AI Model',
            name: 'aiModel',
            type: 'string',
            default: 'n8n-integration',
            description: 'AI model identifier for metadata',
          },
          {
            displayName: 'Application Name',
            name: 'applicationName',
            type: 'string',
            default: 'n8n-workflow',
            description: 'Application name for audit trails',
          },
          {
            displayName: 'Max Polling Duration (Ms)',
            name: 'maxPollingDuration',
            type: 'number',
            default: 300000,
            description: 'Maximum time to wait for async scan completion (5 minutes default)',
            displayOptions: {
              show: {
                '/scanMode': ['async'],
              },
            },
          },
          {
            displayName: 'Max Retries',
            name: 'maxRetries',
            type: 'number',
            default: 3,
            description: 'Maximum number of retry attempts for failed requests',
          },
          {
            displayName: 'Polling Interval (Ms)',
            name: 'pollingInterval',
            type: 'number',
            default: 2000,
            description: 'Polling interval for async scan results (minimum 1000ms)',
            displayOptions: {
              show: {
                '/scanMode': ['async'],
              },
            },
          },
          {
            displayName: 'Timeout (Ms)',
            name: 'timeout',
            type: 'number',
            default: 30000,
            description: 'Request timeout in milliseconds',
          },
          {
            displayName: 'Transaction ID',
            name: 'transactionId',
            type: 'string',
            default: '',
            description: 'Custom transaction ID for tracking. If empty, one will be generated.',
          },
          {
            displayName: 'User ID',
            name: 'userId',
            type: 'string',
            default: 'n8n-user',
            description: 'User identifier for audit trails',
          },
        ],
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const returnData: INodeExecutionData[] = [];
    const credentials = (await this.getCredentials('prismaAirsApi')) as PrismaAirsCredentials;

    const baseUrl = credentials.region === 'eu' 
      ? 'https://service-de.api.aisecurity.paloaltonetworks.com'
      : 'https://service.api.aisecurity.paloaltonetworks.com';

    for (let i = 0; i < items.length; i++) {
      try {
        const operation = this.getNodeParameter('operation', i) as string;
        const scanMode = this.getNodeParameter('scanMode', i) as string;
        const additionalOptions = this.getNodeParameter('additionalOptions', i, {}) as IDataObject;

        const transactionId = (additionalOptions.transactionId as string) || `n8n-${uuidv4()}`;
        const aiModel = (additionalOptions.aiModel as string) || 'n8n-integration';
        const applicationName = (additionalOptions.applicationName as string) || 'n8n-workflow';
        const userId = (additionalOptions.userId as string) || 'n8n-user';
        const timeout = (additionalOptions.timeout as number) || 30000;
        const maxRetries = (additionalOptions.maxRetries as number) || 3;

        let scanContent: ScanContent;
        let scanResult: ScanResponse | AsyncScanResponse;

        // Prepare scan content based on operation
        switch (operation) {
          case 'promptScan': {
            const promptText = this.getNodeParameter('content', i) as string;
            PrismaAirs.validateContentSize(promptText, scanMode);
            scanContent = { prompt: promptText };
            break;
          }
          case 'responseScan': {
            const responseText = this.getNodeParameter('content', i) as string;
            PrismaAirs.validateContentSize(responseText, scanMode);
            scanContent = { response: responseText };
            break;
          }
          case 'dualScan': {
            const promptContent = this.getNodeParameter('promptContent', i) as string;
            const responseContent = this.getNodeParameter('responseContent', i) as string;
            PrismaAirs.validateContentSize(promptContent + responseContent, scanMode);
            scanContent = { prompt: promptContent, response: responseContent };
            break;
          }
          default:
            throw new NodeOperationError(this.getNode(), `Unknown operation: ${operation}`);
        }

        // Prepare scan request
        const scanRequest: ScanRequest = {
          tr_id: transactionId,
          ai_profile: {
            profile_name: credentials.aiProfileName,
          },
          metadata: {
            app_user: userId,
            ai_model: aiModel,
            application_name: applicationName,
          },
          contents: [scanContent],
        };

        // Execute scan based on mode
        const scanner = new PrismaAirsScanner();
        if (scanMode === 'sync') {
          scanResult = await scanner.executeSyncScan(this, baseUrl, scanRequest, timeout, maxRetries);
        } else {
          const pollingInterval = Math.max((additionalOptions.pollingInterval as number) || 2000, 1000);
          const maxPollingDuration = (additionalOptions.maxPollingDuration as number) || 300000;
          scanResult = await scanner.executeAsyncScan(this, baseUrl, scanRequest, timeout, maxRetries, pollingInterval, maxPollingDuration);
        }

        // Prepare output data
        const outputData: IDataObject = {
          operation,
          scanMode,
          transactionId,
          ...scanResult,
          timestamp: new Date().toISOString(),
        };

        returnData.push({
          json: outputData,
          pairedItem: { item: i },
        });

      } catch (error) {
        if (this.continueOnFail()) {
          returnData.push({
            json: {
              error: error instanceof Error ? error.message : 'Unknown error',
              timestamp: new Date().toISOString(),
            },
            pairedItem: { item: i },
          });
        } else {
          throw error;
        }
      }
    }

    return [returnData];
  }

  private static validateContentSize(content: string, scanMode: string): void {
    const contentSize = Buffer.byteLength(content, 'utf8');
    const maxSize = scanMode === 'sync' ? 2 * 1024 * 1024 : 5 * 1024 * 1024; // 2MB for sync, 5MB for async

    if (contentSize > maxSize) {
      throw new ApplicationError(
        `Content size (${Math.round(contentSize / 1024 / 1024)}MB) exceeds ${scanMode} scan limit (${Math.round(maxSize / 1024 / 1024)}MB)`
      );
    }
  }
}