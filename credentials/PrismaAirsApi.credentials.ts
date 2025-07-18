import {
  IAuthenticateGeneric,
  ICredentialTestRequest,
  ICredentialType,
  INodeProperties,
} from 'n8n-workflow';

export class PrismaAirsApi implements ICredentialType {
  name = 'prismaAirsApi';
  displayName = 'Prisma AIRS API';
  documentationUrl = 'https://pan.dev/ai-runtime-security/';
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
      ],
      default: 'us',
      required: true,
      description: 'The region where your Prisma AIRS instance is deployed',
    },
    {
      displayName: 'AI Profile Name',
      name: 'aiProfileName',
      type: 'string',
      default: '',
      required: true,
      description: 'The name of your AI security profile configured in Prisma AIRS',
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
      baseURL: '={{$credentials.region === "eu" ? "https://service-de.api.aisecurity.paloaltonetworks.com" : "https://service.api.aisecurity.paloaltonetworks.com"}}',
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
        type: 'responseSuccessBody',
        properties: {
          message: 'Credential test successful',
          key: 'action',
          value: 'allow',
        },
      },
    ],
  };
}