import { describe, expect, test } from 'vitest'

import { normalizeCustomDomainName } from '../../management/custom-domain-name.js'

const identityProviderHost = 'identity.example.dev'

describe('normalizeCustomDomainName', () => {
  test.each([
    ['lowercases an ASCII host', '  Shop.Example.DEV  ', 'shop.example.dev', 'shop.example.dev'],
    [
      'stores an A-label and displays its U-label',
      'MÜNICH.example.dev',
      'xn--mnich-kva.example.dev',
      'münich.example.dev'
    ],
    [
      'uses non-transitional IDNA2008 processing',
      'faß.example.dev',
      'xn--fa-hia.example.dev',
      'faß.example.dev'
    ],
    [
      'accepts a single-script internationalized label with digits and hyphens',
      'пример-123.example.dev',
      'xn---123-u4dr2awjd.example.dev',
      'пример-123.example.dev'
    ],
    [
      'accepts a 63-character label',
      `${'a'.repeat(63)}.dev`,
      `${'a'.repeat(63)}.dev`,
      `${'a'.repeat(63)}.dev`
    ],
    [
      'accepts a 253-character host',
      `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}`,
      `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}`,
      `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}`
    ]
  ])('%s', (_name, input, host, displayHost) => {
    expect(normalizeCustomDomainName(input, identityProviderHost)).toEqual({
      ok: true,
      host,
      displayHost
    })
  })

  test.each([
    ['empty input', '   ', 'invalid-input'],
    ['a wildcard', '*.example.dev', 'wildcard'],
    ['userinfo', 'user@example.dev', 'userinfo'],
    ['a path', 'example.dev/account', 'path'],
    ['a query', 'example.dev?tenant=one', 'path'],
    ['an IPv4 literal', '127.0.0.1', 'ip-literal'],
    ['a non-canonical IPv4 literal', '127.1', 'ip-literal'],
    ['an IPv6 literal', '[2001:db8::1]', 'ip-literal'],
    ['a port', 'example.dev:443', 'port'],
    ['an ASCII trailing dot', 'example.dev.', 'trailing-dot'],
    ['a mapped trailing dot', 'example.dev。', 'trailing-dot'],
    ['invalid IDNA', '_service.example.dev', 'invalid-domain'],
    ['a 64-character label', `${'a'.repeat(64)}.dev`, 'label-too-long'],
    [
      'a 254-character host',
      `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(62)}`,
      'name-too-long'
    ],
    ['a mixed-script confusable', 'раypal.example.dev', 'mixed-script-confusable'],
    [
      'a mixed-script label whose confusable skeleton is unchanged',
      '例え.example.dev',
      'mixed-script-confusable'
    ],
    ['an RFC 6761 name', 'tenant.example.com', 'special-use'],
    ['an RFC 8375 name', 'router.home.arpa', 'special-use'],
    ['an ICANN public suffix', 'co.uk', 'public-suffix'],
    ['a private public suffix', 'github.io', 'public-suffix'],
    ['the identity provider host', 'IDENTITY.EXAMPLE.DEV', 'identity-provider-domain'],
    ['an identity provider subdomain', 'login.identity.example.dev', 'identity-provider-domain']
  ])('rejects %s', (_name, input, reason) => {
    expect(normalizeCustomDomainName(input, identityProviderHost)).toEqual({ ok: false, reason })
  })
})
