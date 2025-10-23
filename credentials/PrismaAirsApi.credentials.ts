import {
  IAuthenticateGeneric,
  ICredentialTestRequest,
  ICredentialType,
  INodeProperties,
} from 'n8n-workflow';

export class PrismaAirsApi implements ICredentialType {
  name = 'prismaAirsApi';
  displayName = 'Prisma AIRS API';
  documentationUrl = 'https://pan.dev/airs/';
  properties: INodeProperties[] = [
    {
      displayName: 'API Key',
      name: 'apiKey',
      type: 'string',
      typeOptions: {
        password: true,
      },
      default: '',
      required: true,
      description: 'The API key for Prisma AIRS API (x-pan-token)',
    },
    {
      displayName: 'Region',
      name: 'region',
      type: 'options',
      options: [
        {
          name: 'US',
          value: 'us',
        },
        {
          name: 'EU (Germany)',
          value: 'eu',
        },
        {
          name: 'India',
          value: 'in',
        },
        {
          name: 'Custom',
          value: 'custom',
        },
      ],
      default: 'us',
      required: true,
      description: 'The region where your Prisma AIRS instance is deployed',
    },
    {
      displayName: 'Custom Base URL',
      name: 'customBaseUrl',
      type: 'string',
      default: '',
      required: true,
      placeholder: 'https://service-custom.api.aisecurity.paloaltonetworks.com',
      description: 'Custom base URL for Prisma AIRS API (only used when Region is set to Custom)',
      displayOptions: {
        show: {
          region: ['custom'],
        },
      },
    },
    {
      displayName: 'AI Profile',
      name: 'aiProfileName',
      type: 'string',
      default: '',
      required: true,
      placeholder: 'e.g. production-profile or 03b32734-d06d-4bb7-a8df-ac5147630ce8',
      description: 'The AI security profile to use for scans. Accepts profile name or UUID.',
    },
  ];

  authenticate: IAuthenticateGeneric = {
    type: 'generic',
    properties: {
      headers: {
        'x-pan-token': '={{$credentials.apiKey}}',
        'Content-Type': 'application/json',
      },
    },
  };

  test: ICredentialTestRequest = {
    request: {
      baseURL: '={{$credentials.region === "custom" ? $credentials.customBaseUrl : $credentials.region === "eu" ? "https://service-de.api.aisecurity.paloaltonetworks.com" : $credentials.region === "in" ? "https://service-in.api.aisecurity.paloaltonetworks.com" : "https://service.api.aisecurity.paloaltonetworks.com"}}',
      url: '/v1/scan/sync/request',
      method: 'POST',
      body: {
        tr_id: 'n8n-credential-test',
        ai_profile: {
          profile_name: '={{$credentials.aiProfileName}}',
        },
        metadata: {
          app_user: 'n8n-test',
          ai_model: 'test',
          application_name: 'n8n-credential-test',
        },
        contents: [
          {
            prompt: 'Hello, this is a test prompt to verify API credentials.',
          },
        ],
      },
    },
    rules: [
      {
        type: 'responseCode',
        properties: {
          message: 'Credential test successful',
          value: 200,
        },
      },
    ],
  };
}
