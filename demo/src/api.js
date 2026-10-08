import { MANAGEMENT_OPERATIONS, managementApiUrl } from '@custom-domains/contract'

export class ManagementApiError extends Error {
  constructor(response, body) {
    super(body?.error ?? `Request failed (${response.status})`)
    this.name = 'ManagementApiError'
    this.status = response.status
    this.code = body?.code
    this.reason = body?.reason
    this.retryAfter = response.headers.get('retry-after')
  }
}

export function createManagementClient({ issuer, token, fetchImpl = fetch }) {
  async function request(operationId, parameters, body) {
    const operation = MANAGEMENT_OPERATIONS[operationId]
    const response = await fetchImpl(managementApiUrl(issuer, operationId, parameters), {
      method: operation.method,
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { 'content-type': 'application/json' })
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    })

    const payload = response.status === 204 ? undefined : await response.json()
    if (!response.ok) throw new ManagementApiError(response, payload)
    return payload
  }

  return {
    list: () => request('listCustomDomains'),
    add: (host) => request('createCustomDomain', {}, { host }),
    check: (id) => request('createCustomDomainVerificationCheck', { id }),
    reissue: (id) => request('reissueCustomDomainChallenge', { id }),
    remove: (id) => request('deleteCustomDomain', { id })
  }
}
