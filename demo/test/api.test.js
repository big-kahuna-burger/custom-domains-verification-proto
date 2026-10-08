import { describe, expect, test, vi } from 'vitest'
import { createManagementClient, ManagementApiError } from '../src/api.js'

describe('management client', () => {
  test('builds custom-domain requests from the shipped operations', async () => {
    const fetchImpl = vi.fn(async (_url, options) =>
      options.method === 'DELETE'
        ? new Response(undefined, { status: 204 })
        : Response.json(options.method === 'GET' ? [] : {})
    )
    const client = createManagementClient({
      issuer: 'https://identity.example/oidc',
      token: 'scoped-token',
      fetchImpl
    })

    await client.list()
    await client.add('login.example.com')
    await client.check('domain id')
    await client.reissue('domain id')
    await client.remove('domain id')

    expect(fetchImpl.mock.calls.map(([url, options]) => [url, options.method])).toEqual([
      ['https://identity.example/manage/v1/custom-domains', 'GET'],
      ['https://identity.example/manage/v1/custom-domains', 'POST'],
      ['https://identity.example/manage/v1/custom-domains/domain%20id/verification-checks', 'POST'],
      ['https://identity.example/manage/v1/custom-domains/domain%20id/challenge', 'POST'],
      ['https://identity.example/manage/v1/custom-domains/domain%20id', 'DELETE']
    ])
    expect(fetchImpl.mock.calls[1][1].body).toBe('{"host":"login.example.com"}')
    expect(fetchImpl.mock.calls[0][1].headers.authorization).toBe('Bearer scoped-token')
  })

  test('preserves stable error details and retry timing', async () => {
    const client = createManagementClient({
      issuer: 'https://identity.example/oidc',
      token: 'scoped-token',
      fetchImpl: async () =>
        Response.json(
          { error: 'Too Many Requests', code: 'rate_limited' },
          { status: 429, headers: { 'retry-after': '47' } }
        )
    })

    const error = await client.check('domain-id').catch((cause) => cause)

    expect(error).toBeInstanceOf(ManagementApiError)
    expect(error).toMatchObject({ status: 429, code: 'rate_limited', retryAfter: '47' })
  })
})
