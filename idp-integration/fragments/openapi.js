// OpenAPI paths, tag and components for custom domains, as they sat in the IdP's
// openapi-document.js (mounted under /manage/v1).
import {
  createCustomDomainSchema,
  customDomainChallengeSchema,
  customDomainErrorSchema,
  customDomainSchema,
  customDomainVerificationCheckSchema
} from '@custom-domains/contract'

const json = (schema) => ({ 'application/json': { schema } })
const ref = (name) => ({ $ref: `#/components/schemas/${name}` })
// The IdP strips $id from contract schemas before using them as components.
const component = ({ $id, ...schema }) => schema
const customDomainId = {
  name: 'id',
  in: 'path',
  description: 'Custom domain ID',
  required: true,
  schema: { type: 'string', format: 'uuid' }
}
const customDomainErrors = {
  401: { description: 'Missing or invalid token', content: json(ref('ManagementError')) },
  403: { description: 'Missing scope', content: json(ref('ManagementError')) }
}
const customDomainNotFound = {
  404: {
    description: 'Missing and removed domains are indistinguishable',
    content: json(ref('ManagementError'))
  }
}

export const customDomainsTag = {
  name: 'Custom domains',
  description: "This identity provider's custom domains and their DNS ownership challenge."
}

export const customDomainPaths = {
  '/custom-domains': {
    get: {
      tags: ['Custom domains'],
      summary: 'List the custom domains',
      description: 'Removed domains are excluded. Ordered by creation time.',
      operationId: 'listCustomDomains',
      security: [{ managementOAuth: ['read:custom_domains'] }, { jwt: [] }],
      responses: {
        200: {
          description: 'Custom domains',
          content: json({ type: 'array', items: ref('CustomDomain') })
        },
        ...customDomainErrors
      }
    },
    post: {
      tags: ['Custom domains'],
      summary: 'Add a custom domain',
      description:
        'Starts ownership verification. The response holds the TXT record to publish; its value is shown only here and on reissue. This identity provider holds at most 10 domains.',
      operationId: 'createCustomDomain',
      security: [{ managementOAuth: ['write:custom_domains'] }, { jwt: [] }],
      requestBody: {
        required: true,
        content: json({ ...ref('CreateCustomDomain'), example: { host: 'login.attest.me' } })
      },
      responses: {
        201: { description: 'Domain added', content: json(ref('CustomDomainWithChallenge')) },
        400: {
          description: 'Invalid host (code invalid_host, with a reason)',
          content: json(ref('CustomDomainError'))
        },
        ...customDomainErrors,
        409: {
          description:
            'Host already claimed (code host_taken) or domain limit reached (code domain_limit_reached)',
          content: json(ref('CustomDomainError'))
        }
      }
    }
  },
  '/custom-domains/{id}': {
    get: {
      tags: ['Custom domains'],
      summary: 'Get a custom domain',
      operationId: 'getCustomDomain',
      security: [{ managementOAuth: ['read:custom_domains'] }, { jwt: [] }],
      parameters: [customDomainId],
      responses: {
        200: { description: 'Custom domain', content: json(ref('CustomDomain')) },
        ...customDomainErrors,
        ...customDomainNotFound
      }
    },
    delete: {
      tags: ['Custom domains'],
      summary: 'Remove a custom domain',
      operationId: 'deleteCustomDomain',
      security: [{ managementOAuth: ['delete:custom_domains'] }, { jwt: [] }],
      parameters: [customDomainId],
      responses: {
        204: { description: 'Domain removed' },
        ...customDomainErrors,
        ...customDomainNotFound
      }
    }
  },
  '/custom-domains/{id}/verification-checks': {
    post: {
      tags: ['Custom domains'],
      summary: 'Check domain ownership now',
      description:
        'Looks up the TXT record at the challenge name and verifies the domain when it matches. Limited to one check per domain and ten in total per minute.',
      operationId: 'createCustomDomainVerificationCheck',
      security: [{ managementOAuth: ['update:custom_domains'] }, { jwt: [] }],
      parameters: [customDomainId],
      responses: {
        200: { description: 'Check result', content: json(ref('CustomDomainVerificationCheck')) },
        ...customDomainErrors,
        ...customDomainNotFound,
        429: {
          description: 'Check limit reached (code rate_limited); see Retry-After',
          headers: { 'Retry-After': { schema: { type: 'integer', minimum: 1 } } },
          content: json(ref('CustomDomainError'))
        },
        503: {
          description: 'DNS resolvers are not configured',
          content: json(ref('ManagementError'))
        }
      }
    }
  },
  '/custom-domains/{id}/challenge': {
    post: {
      tags: ['Custom domains'],
      summary: 'Reissue the ownership challenge',
      description:
        'Replaces the challenge with a new one and returns the domain to pending. The previous TXT value stops verifying.',
      operationId: 'reissueCustomDomainChallenge',
      security: [{ managementOAuth: ['update:custom_domains'] }, { jwt: [] }],
      parameters: [customDomainId],
      responses: {
        200: {
          description: 'New challenge',
          content: json(ref('CustomDomainWithChallenge'))
        },
        ...customDomainErrors,
        ...customDomainNotFound
      }
    }
  }
}

export const customDomainComponents = {
  CreateCustomDomain: component(createCustomDomainSchema),
  CustomDomain: component(customDomainSchema),
  CustomDomainChallenge: component(customDomainChallengeSchema),
  CustomDomainWithChallenge: {
    type: 'object',
    additionalProperties: false,
    properties: {
      domain: ref('CustomDomain'),
      challenge: ref('CustomDomainChallenge')
    },
    required: ['domain', 'challenge']
  },
  CustomDomainVerificationCheck: {
    ...component(customDomainVerificationCheckSchema),
    properties: {
      ...customDomainVerificationCheckSchema.properties,
      domain: ref('CustomDomain')
    }
  },
  CustomDomainError: component(customDomainErrorSchema)
}
