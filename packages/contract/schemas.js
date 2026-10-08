import { CUSTOM_DOMAIN_ERRORS, CUSTOM_DOMAIN_RESPONSE_STATES } from './constants.js'

const timestamp = { type: 'string', format: 'date-time' }
const nullableTimestamp = { type: ['string', 'null'], format: 'date-time' }

export const createCustomDomainSchema = {
  $id: 'createCustomDomain',
  type: 'object',
  additionalProperties: false,
  properties: {
    host: {
      type: 'string',
      minLength: 1,
      maxLength: 253,
      description:
        'Host name to verify, in Unicode or A-label form. Wildcards, IP literals, ports, paths, public suffixes and the identity provider host are rejected.'
    }
  },
  required: ['host']
}

export const customDomainParamsSchema = {
  $id: 'customDomainParams',
  type: 'object',
  additionalProperties: false,
  properties: { id: { type: 'string', format: 'uuid' } },
  required: ['id']
}

export const customDomainSchema = {
  $id: 'customDomain',
  type: 'object',
  additionalProperties: false,
  properties: {
    id: { type: 'string', format: 'uuid' },
    host: { type: 'string', description: 'Canonical A-label host.' },
    displayHost: { type: 'string', description: 'Unicode host for display.' },
    state: { type: 'string', enum: CUSTOM_DOMAIN_RESPONSE_STATES },
    challengeExpiresAt: timestamp,
    lastCheckedAt: nullableTimestamp,
    verifiedAt: nullableTimestamp,
    lastFailureReason: { type: ['string', 'null'] },
    createdAt: timestamp,
    updatedAt: timestamp
  },
  required: [
    'id',
    'host',
    'displayHost',
    'state',
    'challengeExpiresAt',
    'lastCheckedAt',
    'verifiedAt',
    'lastFailureReason',
    'createdAt',
    'updatedAt'
  ]
}

export const customDomainChallengeSchema = {
  $id: 'customDomainChallenge',
  type: 'object',
  additionalProperties: false,
  description:
    'Ownership TXT record to publish. The value is returned only by add and reissue and is never stored or returned again.',
  properties: {
    recordName: { type: 'string' },
    recordType: { type: 'string', enum: ['TXT'] },
    recordValue: { type: 'string' },
    expiresAt: timestamp
  },
  required: ['recordName', 'recordType', 'recordValue', 'expiresAt']
}

export const customDomainWithChallengeSchema = {
  $id: 'customDomainWithChallenge',
  type: 'object',
  additionalProperties: false,
  properties: {
    domain: customDomainSchema,
    challenge: customDomainChallengeSchema
  },
  required: ['domain', 'challenge']
}

export const customDomainVerificationCheckSchema = {
  $id: 'customDomainVerificationCheck',
  type: 'object',
  additionalProperties: false,
  properties: {
    verified: { type: 'boolean' },
    reason: {
      type: 'string',
      description: 'Why the check did not verify the domain. Absent when verified.'
    },
    retryable: { type: 'boolean' },
    domain: customDomainSchema
  },
  required: ['verified', 'retryable', 'domain']
}

export const customDomainErrorSchema = {
  $id: 'customDomainError',
  type: 'object',
  additionalProperties: false,
  properties: {
    error: {
      type: 'string',
      enum: [...new Set(Object.values(CUSTOM_DOMAIN_ERRORS).map(({ error }) => error))]
    },
    code: { type: 'string', enum: Object.values(CUSTOM_DOMAIN_ERRORS).map(({ code }) => code) },
    reason: { type: 'string', description: 'Host validation failure reason for invalid_host.' }
  },
  required: ['error', 'code']
}

