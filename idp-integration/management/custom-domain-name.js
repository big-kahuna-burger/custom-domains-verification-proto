import { isIP } from 'node:net'

import { parse as parseDomain } from 'tldts'
import tr46 from 'tr46'
import unicodeProperties from 'unicode-properties'
import { z } from 'zod'

const hostInputSchema = z.string().trim().min(1)

const idnaOptions = {
  checkBidi: true,
  checkHyphens: true,
  checkJoiners: true,
  transitionalProcessing: false,
  useSTD3ASCIIRules: true
}

const specialUseSuffixes = [
  'test',
  'localhost',
  'invalid',
  'example',
  'example.com',
  'example.net',
  'example.org',
  'home.arpa'
]

function rejected(reason) {
  return { ok: false, reason }
}

function isIpLiteral(value) {
  const unbracketed = value.startsWith('[') && value.endsWith(']') ? value.slice(1, -1) : value
  if (isIP(unbracketed) !== 0) return true

  try {
    const parsed = new URL(`http://${value}`)
    const hostname = parsed.hostname.startsWith('[')
      ? parsed.hostname.slice(1, -1)
      : parsed.hostname
    return isIP(hostname) !== 0
  } catch {
    return false
  }
}

function isSpecialUse(host) {
  return specialUseSuffixes.some((suffix) => host === suffix || host.endsWith(`.${suffix}`))
}

function hasMixedScriptLabel(host) {
  return host.split('.').some((label) => {
    const scripts = new Set()

    for (const character of label) {
      const script = unicodeProperties.getScript(character.codePointAt(0))
      if (script !== 'Common' && script !== 'Inherited' && script !== 'Unknown') {
        scripts.add(script)
      }
    }

    return scripts.size > 1
  })
}

function toAscii(value) {
  return tr46.toASCII(value, idnaOptions)
}

/**
 * Canonicalizes a custom-domain host without performing I/O.
 *
 * Successful results contain the A-label for storage and U-label for display.
 */
export function normalizeCustomDomainName(input, identityProviderHost) {
  const parsedInput = hostInputSchema.safeParse(input)
  if (!parsedInput.success) return rejected('invalid-input')

  const value = parsedInput.data
  if (value.includes('*')) return rejected('wildcard')
  if (value.includes('@')) return rejected('userinfo')
  if (value.includes('/') || value.includes('\\') || value.includes('?') || value.includes('#')) {
    return rejected('path')
  }
  if (isIpLiteral(value)) return rejected('ip-literal')
  if (value.includes(':')) return rejected('port')

  const host = toAscii(value)
  if (host === null) return rejected('invalid-domain')
  if (host.endsWith('.')) return rejected('trailing-dot')

  const labels = host.split('.')
  if (labels.some((label) => label.length > 63)) return rejected('label-too-long')
  if (host.length > 253) return rejected('name-too-long')

  const unicodeResult = tr46.toUnicode(host, idnaOptions)
  if (unicodeResult.error) return rejected('invalid-domain')
  const displayHost = unicodeResult.domain
  if (hasMixedScriptLabel(displayHost)) return rejected('mixed-script-confusable')

  if (isSpecialUse(host)) return rejected('special-use')

  const suffix = parseDomain(host, {
    allowPrivateDomains: true,
    extractHostname: false
  })
  if ((suffix.isIcann || suffix.isPrivate) && suffix.publicSuffix === host) {
    return rejected('public-suffix')
  }

  const parsedIdentityProviderHost = hostInputSchema.safeParse(identityProviderHost)
  if (!parsedIdentityProviderHost.success) return rejected('invalid-identity-provider-host')
  const canonicalIdentityProviderHost = toAscii(parsedIdentityProviderHost.data)
  if (canonicalIdentityProviderHost === null || canonicalIdentityProviderHost.endsWith('.')) {
    return rejected('invalid-identity-provider-host')
  }
  if (
    host === canonicalIdentityProviderHost ||
    host.endsWith(`.${canonicalIdentityProviderHost}`)
  ) {
    return rejected('identity-provider-domain')
  }

  return { ok: true, host, displayHost }
}

/**
 * Unicode display form of a stored A-label host. Falls back to the A-label when it cannot be
 * converted, so a response always has a display host.
 */
export function customDomainDisplayHost(host) {
  const result = tr46.toUnicode(host, idnaOptions)
  return result.error ? host : result.domain
}
