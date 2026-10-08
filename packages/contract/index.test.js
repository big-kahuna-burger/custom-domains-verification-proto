import assert from 'node:assert/strict'
import test from 'node:test'
import {
  CUSTOM_DOMAIN_ERRORS,
  CUSTOM_DOMAIN_RESPONSE_STATES,
  createCustomDomainSchema,
  customDomainErrorSchema,
  customDomainSchema,
  customDomainWithChallengeSchema,
  MANAGEMENT_OPERATIONS,
  MANAGEMENT_PERMISSIONS,
  managementApiUrl
} from './index.js'

test('publishes custom-domain operations behind dedicated scopes', () => {
  assert.deepEqual(MANAGEMENT_PERMISSIONS.customDomains, {
    read: 'read:custom_domains',
    write: 'write:custom_domains',
    update: 'update:custom_domains',
    delete: 'delete:custom_domains'
  })
  assert.deepEqual(
    Object.fromEntries(
      Object.entries(MANAGEMENT_OPERATIONS)
        .filter(([name]) => name.includes('CustomDomain'))
        .map(([name, { method, path, permission, documented, implemented }]) => [
          name,
          [method, path, permission, documented, implemented]
        ])
    ),
    {
      listCustomDomains: ['GET', '/custom-domains', 'read:custom_domains', true, true],
      createCustomDomain: ['POST', '/custom-domains', 'write:custom_domains', true, true],
      getCustomDomain: ['GET', '/custom-domains/{id}', 'read:custom_domains', true, true],
      deleteCustomDomain: ['DELETE', '/custom-domains/{id}', 'delete:custom_domains', true, true],
      createCustomDomainVerificationCheck: [
        'POST',
        '/custom-domains/{id}/verification-checks',
        'update:custom_domains',
        true,
        true
      ],
      reissueCustomDomainChallenge: [
        'POST',
        '/custom-domains/{id}/challenge',
        'update:custom_domains',
        true,
        true
      ]
    }
  )
  assert.equal(
    managementApiUrl('https://identity.example/oidc', 'createCustomDomainVerificationCheck', {
      id: 'b5c1f1a0-0000-4000-8000-000000000000'
    }),
    'https://identity.example/manage/v1/custom-domains/b5c1f1a0-0000-4000-8000-000000000000/verification-checks'
  )
})

test('custom-domain schemas never expose challenge secrets on reads', () => {
  assert.deepEqual(createCustomDomainSchema.required, ['host'])
  assert.equal(createCustomDomainSchema.additionalProperties, false)
  assert.equal('tenantId' in createCustomDomainSchema.properties, false)

  for (const property of ['tenantId', 'challengeHash', 'recordValue']) {
    assert.equal(property in customDomainSchema.properties, false, property)
  }
  assert.deepEqual(customDomainSchema.properties.state.enum, CUSTOM_DOMAIN_RESPONSE_STATES)
  assert.equal(CUSTOM_DOMAIN_RESPONSE_STATES.includes('removed'), false)
  assert.deepEqual(customDomainWithChallengeSchema.required, ['domain', 'challenge'])
})

test('custom-domain errors have distinct stable codes', () => {
  const codes = Object.values(CUSTOM_DOMAIN_ERRORS).map(({ code }) => code)
  assert.equal(new Set(codes).size, codes.length)
  assert.deepEqual(
    [CUSTOM_DOMAIN_ERRORS.hostTaken.statusCode, CUSTOM_DOMAIN_ERRORS.domainLimitReached.statusCode],
    [409, 409]
  )
  assert.deepEqual(customDomainErrorSchema.properties.code.enum, codes)
})
