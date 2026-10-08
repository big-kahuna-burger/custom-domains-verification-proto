// Response mappers, as they sat in the IdP's management/dtos.js.

const isoOrNull = (value) => (value ? new Date(value).toISOString() : null)

/**
 * Readable custom-domain fields only: never the challenge hash or the TXT value.
 * @param {object} domain
 * @param {(host: string) => string} displayHost
 */
export function customDomainDTO(domain, displayHost) {
  return {
    id: domain.id,
    host: domain.host,
    displayHost: displayHost(domain.host),
    state: domain.state,
    challengeExpiresAt: isoOrNull(domain.challengeExpiresAt),
    lastCheckedAt: isoOrNull(domain.lastCheckedAt),
    verifiedAt: isoOrNull(domain.verifiedAt),
    lastFailureReason: domain.lastFailureReason ?? null,
    createdAt: isoOrNull(domain.createdAt),
    updatedAt: isoOrNull(domain.updatedAt)
  }
}

/** The ownership TXT instruction returned once by add and reissue. */
export function customDomainChallengeDTO(challenge) {
  return {
    recordName: challenge.name,
    recordType: 'TXT',
    recordValue: challenge.value,
    expiresAt: new Date(challenge.expiresAt).toISOString()
  }
}
