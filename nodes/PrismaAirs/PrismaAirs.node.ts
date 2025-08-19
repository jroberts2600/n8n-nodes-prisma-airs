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

import { randomUUID } from 'node:crypto';

interface PrismaAirsCredentials extends ICredentialDataDecryptedObject {
  apiKey: string;
  region: string;
  aiProfileName: string;
}

interface ScanContent {
  prompt?: string;
  response?: string;
  context?: string;
}

interface ScanRequest {
  tr_id: string;
  ai_profile: {
    profile_name?: string;
    profile_id?: string;
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
  prompt_masked_data?: string;
  response_masked_data?: string;
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
        
        if ((result as any).status === 'completed' || (result as any).action) {
          return result as ScanResponse;
        } else if ((result as any).status === 'failed') {
          throw new ApplicationError(`Async scan failed: ${(result as any).error || 'Unknown error'}`);
        }
        
        // Wait before next poll
        await new Promise(resolve => setTimeout(resolve, pollingInterval));
      } catch (error) {
        const code = (error as any).httpCode as number | string | undefined;
        const is404 = typeof code === 'number' ? code === 404 : String(code) === '404';
        if (is404) {
          // Scan not ready yet, continue polling
          await new Promise(resolve => setTimeout(resolve, pollingInterval));
          continue;
        }
        throw error;
      }
    }

    throw new ApplicationError('Async scan timed out waiting for results');
  }

  async executeBatchScan(
    context: IExecuteFunctions,
    baseUrl: string,
    scanRequests: ScanRequest[],
    scanMode: string,
    timeout: number,
    maxRetries: number,
    pollingInterval?: number,
    maxPollingDuration?: number
  ): Promise<ScanResponse[]> {
    const results: ScanResponse[] = [];
    
    // Process in batches of 5 (API limit)
    const batchSize = 5;
    for (let i = 0; i < scanRequests.length; i += batchSize) {
      const batch = scanRequests.slice(i, i + batchSize);
      const batchPromises = batch.map(async (scanRequest) => {
        if (scanMode === 'sync') {
          return this.executeSyncScan(context, baseUrl, scanRequest, timeout, maxRetries);
        } else {
          return this.executeAsyncScan(
            context, 
            baseUrl, 
            scanRequest, 
            timeout, 
            maxRetries, 
            pollingInterval || 2000, 
            maxPollingDuration || 300000
          );
        }
      });
      
      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
    }
    
    return results;
  }

  async executeMaskingScan(
    context: IExecuteFunctions,
    baseUrl: string,
    scanRequest: ScanRequest,
    scanMode: string,
    timeout: number,
    maxRetries: number,
    pollingInterval?: number,
    maxPollingDuration?: number
  ): Promise<{ scanResult: ScanResponse; maskedContent: string; maskApplied: boolean; dlpDetected: boolean }> {
    // Execute scan based on mode
    let scanResult: ScanResponse;
    if (scanMode === 'sync') {
      scanResult = await this.executeSyncScan(context, baseUrl, scanRequest, timeout, maxRetries);
    } else {
      scanResult = await this.executeAsyncScan(
        context,
        baseUrl,
        scanRequest,
        timeout,
        maxRetries,
        pollingInterval || 2000,
        maxPollingDuration || 300000
      );
    }
    
    // Get the original content
    const originalContent = scanRequest.contents[0].prompt || scanRequest.contents[0].response || '';
    let maskedContent = originalContent;
    let maskApplied = false;
    
    // Check if API provided masked content
    // Note: API returns masked data in prompt_masked_data or response_masked_data when configured
    const response = scanResult as any;
    
    // Check if DLP was detected
    const dlpDetected = response.prompt_detected?.dlp === true || 
                       response.response_detected?.dlp === true ||
                       response.dlp === true;
    
    // Check for API-provided masked content
    // The API returns masked content when DLP is detected AND masking is enabled in the profile
    if (response.prompt_masked_data && response.prompt_masked_data !== null) {
      maskedContent = response.prompt_masked_data;
      maskApplied = true;
    } else if (response.response_masked_data && response.response_masked_data !== null) {
      maskedContent = response.response_masked_data;
      maskApplied = true;
    }
    // If DLP detected but no masked data, the profile may not have masking enabled
    // We return the original content and let the user know via the dlpDetected flag
    
    return { scanResult, maskedContent, maskApplied, dlpDetected };
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
          const code = (error as any).httpCode as number | string | undefined;
          const is4xx = typeof code === 'number' ? code >= 400 && code < 500 : /^4\d\d$/.test(String(code || ''));
          if (is4xx) {
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
  private static getBaseURL(region: string): string {
    if (region === 'eu') return 'https://service-de.api.aisecurity.paloaltonetworks.com';
    if (region === 'us') return 'https://service.api.aisecurity.paloaltonetworks.com';
    throw new ApplicationError(`Unknown region "${region}". Expected "us" or "eu".`);
  }

  private static isUUID(value: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return uuidRegex.test(value);
  }

  private static createProfileObject(profileValue: string): { profile_name?: string; profile_id?: string } {
    if (this.isUUID(profileValue)) {
      return { profile_id: profileValue };
    }
    return { profile_name: profileValue };
  }
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
            name: 'Batch Scan',
            value: 'batchScan',
            description: 'Scan multiple items in a single operation (up to 5)',
            action: 'Perform batch scanning of multiple items',
          },
          {
            name: 'Dual Scan',
            value: 'dualScan',
            description: 'Scan both prompt and response in sequence',
            action: 'Perform dual scanning of prompt and response',
          },
          {
            name: 'Mask Data',
            value: 'maskData',
            description: 'Scan and mask sensitive data in content',
            action: 'Scan and mask sensitive data',
          },
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
        requiresDataPath: 'single',
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
        requiresDataPath: 'single',
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
        requiresDataPath: 'single',
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
        displayName: 'Context',
        name: 'context',
        type: 'string',
        typeOptions: {
          rows: 4,
        },
        default: '',
        description: 'Optional context for grounding validation (up to 100K characters)',
        displayOptions: {
          show: {
            operation: ['dualScan'],
          },
        },
      },
      {
        displayName: 'Batch Items',
        name: 'batchItems',
        type: 'fixedCollection',
        typeOptions: {
          multipleValues: true,
          maxValue: 5,
        },
        default: {},
        description: 'Items to scan in batch (maximum 5 items)',
        displayOptions: {
          show: {
            operation: ['batchScan'],
          },
        },
        options: [
          {
            name: 'items',
            displayName: 'Item',
            values: [
              {
                displayName: 'Item Type',
                name: 'itemType',
                type: 'options',
                options: [
                  {
                    name: 'Prompt',
                    value: 'prompt',
                  },
                  {
                    name: 'Response',
                    value: 'response',
                  },
                  {
                    name: 'Both',
                    value: 'both',
                  },
                ],
                default: 'prompt',
              },
              {
                displayName: 'Prompt Content',
                name: 'promptContent',
                type: 'string',
                typeOptions: {
                  rows: 2,
                },
                default: '',
                displayOptions: {
                  show: {
                    itemType: ['prompt', 'both'],
                  },
                },
              },
              {
                displayName: 'Response Content',
                name: 'responseContent',
                type: 'string',
                typeOptions: {
                  rows: 2,
                },
                default: '',
                displayOptions: {
                  show: {
                    itemType: ['response', 'both'],
                  },
                },
              },
            ],
          },
        ],
      },
      {
        displayName: 'Content to Mask',
        name: 'maskContent',
        type: 'string',
        requiresDataPath: 'single',
        typeOptions: {
          rows: 4,
        },
        default: '',
        required: true,
        description: 'The content to scan for sensitive data. If detected, Prisma AIRS will return masked content.',
        displayOptions: {
          show: {
            operation: ['maskData'],
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
            displayName: 'AI Profile Override',
            name: 'aiProfileOverride',
            type: 'string',
            default: '',
            description: 'Override the default AI profile. Accepts profile name or UUID (e.g., "production-profile" or "03b32734-d06d-4bb7-a8df-ac5147630ce8"). Leave empty to use credential profile.',
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

    const baseUrl = PrismaAirs.getBaseURL(credentials.region);

    for (let i = 0; i < items.length; i++) {
      try {
        const operation = this.getNodeParameter('operation', i) as string;
        const scanMode = this.getNodeParameter('scanMode', i) as string;
        const additionalOptions = this.getNodeParameter('additionalOptions', i, {}) as IDataObject;

        const transactionId = (additionalOptions.transactionId as string) || `n8n-${randomUUID()}`;
        const aiModel = (additionalOptions.aiModel as string) || 'n8n-integration';
        const applicationName = (additionalOptions.applicationName as string) || 'n8n-workflow';
        const userId = (additionalOptions.userId as string) || 'n8n-user';
        const timeout = (additionalOptions.timeout as number) || 30000;
        const rawMaxRetries = (additionalOptions.maxRetries as number) || 3;
        const maxRetries = Math.min(rawMaxRetries, 6);
        const aiProfileOverride = (additionalOptions.aiProfileOverride as string) || '';
        const profileToUse = aiProfileOverride || credentials.aiProfileName;

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
            const context = this.getNodeParameter('context', i, '') as string;
            PrismaAirs.validateContentSize(promptContent + responseContent + context, scanMode);
            scanContent = { prompt: promptContent, response: responseContent };
            if (context) {
              scanContent.context = context;
            }
            break;
          }
          case 'batchScan': {
            // Handle batch scan operation
            const batchItems = this.getNodeParameter('batchItems', i, {}) as IDataObject;
            const itemsArray = (batchItems.items as IDataObject[]) || [];
            
            if (itemsArray.length === 0) {
              throw new NodeOperationError(this.getNode(), 'At least one item is required for batch scanning');
            }
            
            const scanRequests: ScanRequest[] = itemsArray.map((item, index) => {
              const itemType = item.itemType as string;
              const itemContent: ScanContent = {};
              
              if (itemType === 'prompt' || itemType === 'both') {
                itemContent.prompt = item.promptContent as string;
              }
              if (itemType === 'response' || itemType === 'both') {
                itemContent.response = item.responseContent as string;
              }
              
              // Validate each item's size
              const contentSize = (itemContent.prompt || '') + (itemContent.response || '');
              PrismaAirs.validateContentSize(contentSize, scanMode);
              
              return {
                tr_id: `${transactionId}-batch-${index}`,
                ai_profile: PrismaAirs.createProfileObject(profileToUse),
                metadata: {
                  app_user: userId,
                  ai_model: aiModel,
                  application_name: applicationName,
                },
                contents: [itemContent],
              };
            });
            
            // Execute batch scan
            const scanner = new PrismaAirsScanner();
            const batchResults = await scanner.executeBatchScan(
              this,
              baseUrl,
              scanRequests,
              scanMode,
              timeout,
              maxRetries,
              scanMode === 'async' ? Math.max((additionalOptions.pollingInterval as number) || 2000, 1000) : undefined,
              scanMode === 'async' ? (additionalOptions.maxPollingDuration as number) || 300000 : undefined
            );
            
            // Return all batch results
            batchResults.forEach((result, index) => {
              returnData.push({
                json: {
                  operation,
                  scanMode,
                  batchIndex: index,
                  transactionId: `${transactionId}-batch-${index}`,
                  ...result,
                  timestamp: new Date().toISOString(),
                },
                pairedItem: { item: i },
              });
            });
            
            continue; // Skip the regular single-scan processing
          }
          case 'maskData': {
            const maskContent = this.getNodeParameter('maskContent', i) as string;
            PrismaAirs.validateContentSize(maskContent, scanMode);
            
            // Prepare scan request for masking
            const maskScanRequest: ScanRequest = {
              tr_id: transactionId,
              ai_profile: PrismaAirs.createProfileObject(profileToUse),
              metadata: {
                app_user: userId,
                ai_model: aiModel,
                application_name: applicationName,
              },
              contents: [{ response: maskContent }], // Treat as response for DLP detection
            };
            
            // Execute masking scan
            const scanner = new PrismaAirsScanner();
            const { scanResult: maskResult, maskedContent, maskApplied, dlpDetected } = await scanner.executeMaskingScan(
              this,
              baseUrl,
              maskScanRequest,
              scanMode,
              timeout,
              maxRetries,
              scanMode === 'async' ? Math.max((additionalOptions.pollingInterval as number) || 2000, 1000) : undefined,
              scanMode === 'async' ? (additionalOptions.maxPollingDuration as number) || 300000 : undefined
            );
            
            // Return masking result
            returnData.push({
              json: {
                operation,
                scanMode,
                transactionId,
                originalContent: maskContent,
                maskedContent,
                maskApplied,
                dlpDetected,
                maskingNote: dlpDetected && !maskApplied ? 
                  'DLP detected but no masked content returned. Profile may not have masking enabled.' : 
                  undefined,
                ...maskResult,
                timestamp: new Date().toISOString(),
              },
              pairedItem: { item: i },
            });
            
            continue; // Skip the regular single-scan processing
          }
          default:
            throw new NodeOperationError(this.getNode(), `Unknown operation: ${operation}`);
        }

        // Prepare scan request
        const scanRequest: ScanRequest = {
          tr_id: transactionId,
          ai_profile: PrismaAirs.createProfileObject(profileToUse),
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