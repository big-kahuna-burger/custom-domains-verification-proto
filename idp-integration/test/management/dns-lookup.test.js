import dnsPacket from 'dns-packet'
import { describe, expect, it, vi } from 'vitest'
import { DnsLookupError, createInMemoryDnsLookup } from '../../management/dns-lookup.js'
import { createDnsWireQuery } from '../../management/dns-wire-query.js'
import { createNodeDnsLookup } from '../../management/node-dns-lookup.js'

const cnameZone = (hops) => {
  const zone = {}
  for (let hop = 0; hop < hops; hop += 1) {
    const owner = `hop-${hop}.example.com`
    const target = `hop-${hop + 1}.example.com`
    zone[owner] = { cname: [target] }
  }
  zone[`hop-${hops}.example.com`] = { txt: ['terminal'] }
  return zone
}

const rejectsWith = async (promise, code) => {
  const error = await promise.then(
    () => null,
    (caught) => caught
  )
  expect(error).toBeInstanceOf(DnsLookupError)
  expect(error.code).toBe(code)
  return error
}

describe('in-memory DNS lookup fake', () => {
  const dns = createInMemoryDnsLookup({
    zone: {
      'example.com': { txt: [['v=one', 'two'], 'plain'] },
      'alias.example.com': { cname: ['TARGET.EXAMPLE.NET.'] },
      'target.example.net': { txt: ['terminal'] },
      'broken.example.com': { error: 'SERVFAIL' }
    },
    bounds: { maxRecords: 2, maxRecordLength: 24 }
  })

  it('concatenates multi-string TXT values without separators', async () => {
    expect(await dns.lookupTxt('example.com')).toEqual(['v=onetwo', 'plain'])
    expect(await dns.lookupCname('alias.example.com')).toEqual(['target.example.net'])
  })

  it('reports NXDOMAIN, NODATA and transient failures with retryability', async () => {
    const missing = await rejectsWith(dns.lookupTxt('missing.example.com'), 'NXDOMAIN')
    expect(missing).toMatchObject({ retryable: false, retryAfterSeconds: 60 })
    const noData = await rejectsWith(dns.lookupTxt('alias.example.com'), 'NODATA')
    expect(noData).toMatchObject({ retryable: false, retryAfterSeconds: 60 })
    expect((await rejectsWith(dns.lookupTxt('broken.example.com'), 'SERVFAIL')).retryable).toBe(
      true
    )
  })

  it('derives deterministic negative-cache delays from the fake SOA', async () => {
    const negative = createInMemoryDnsLookup({
      zone: {
        'missing.example.com': { error: 'NXDOMAIN', soa: { ttl: 900, minimum: 120 } },
        'empty.example.com': { soa: { ttl: 30, minimum: 300 } }
      }
    })
    expect(
      (await rejectsWith(negative.lookupTxt('missing.example.com'), 'NXDOMAIN')).retryAfterSeconds
    ).toBe(120)
    expect(
      (await rejectsWith(negative.lookupTxt('empty.example.com'), 'NODATA')).retryAfterSeconds
    ).toBe(30)
  })

  it('falls back for malformed SOA values and clamps configured bounds', async () => {
    const negative = createInMemoryDnsLookup({
      zone: {
        'malformed.example.com': { error: 'NXDOMAIN', soa: { ttl: -1, minimum: 5 } },
        'short.example.com': { error: 'NXDOMAIN', soa: { ttl: 1, minimum: 2 } },
        'long.example.com': { error: 'NXDOMAIN', soa: { ttl: 900, minimum: 800 } }
      },
      bounds: {
        negativeCacheMinSeconds: 10,
        negativeCacheMaxSeconds: 300,
        negativeCacheFallbackSeconds: 5
      }
    })
    expect(
      (await rejectsWith(negative.lookupTxt('malformed.example.com'), 'NXDOMAIN')).retryAfterSeconds
    ).toBe(10)
    expect(
      (await rejectsWith(negative.lookupTxt('short.example.com'), 'NXDOMAIN')).retryAfterSeconds
    ).toBe(10)
    expect(
      (await rejectsWith(negative.lookupTxt('long.example.com'), 'NXDOMAIN')).retryAfterSeconds
    ).toBe(300)
  })

  it('rejects malformed names without a lookup', async () => {
    for (const name of [
      '-a.example.com',
      'a-.example.com',
      '',
      'Example.com',
      'a..com',
      'example.com.',
      'bad name.com',
      'é.com'
    ]) {
      await rejectsWith(dns.lookupTxt(name), 'INVALID_NAME')
    }
    await rejectsWith(dns.lookupTxt(`${'a'.repeat(64)}.com`), 'INVALID_NAME')
    await rejectsWith(dns.lookupTxt(undefined), 'INVALID_NAME')
  })

  it('rejects oversized answers instead of truncating them', async () => {
    const big = createInMemoryDnsLookup({
      zone: {
        'many.example.com': { txt: ['a', 'b', 'c'] },
        'long.example.com': { txt: ['x'.repeat(25)] }
      },
      bounds: { maxRecords: 2, maxRecordLength: 24 }
    })
    await rejectsWith(big.lookupTxt('many.example.com'), 'INVALID_RESPONSE')
    await rejectsWith(big.lookupTxt('long.example.com'), 'INVALID_RESPONSE')
  })

  it('returns the full chain at the eight-hop limit', async () => {
    const dns = createInMemoryDnsLookup({ zone: cnameZone(8) })
    const chain = await dns.lookupCname('hop-0.example.com')
    const expected = Array.from({ length: 8 }, (_, index) => `hop-${index + 1}.example.com`)
    expect(chain).toEqual(expected)
  })

  it('rejects an over-limit chain with a stable non-retryable outcome', async () => {
    const dns = createInMemoryDnsLookup({ zone: cnameZone(9) })
    const lookup = dns.lookupCname('hop-0.example.com')
    const error = await rejectsWith(lookup, 'CNAME_DEPTH_EXCEEDED')
    expect(error.retryable).toBe(false)
  })

  it('rejects loops with a stable non-retryable outcome', async () => {
    const dns = createInMemoryDnsLookup({
      zone: {
        'a.example.com': { cname: ['b.example.com'] },
        'b.example.com': { cname: ['a.example.com'] }
      }
    })
    const error = await rejectsWith(dns.lookupCname('a.example.com'), 'CNAME_LOOP')
    expect(error.retryable).toBe(false)
  })
})

describe('DNS lookup edge cases', () => {
  it('counts record length in UTF-8 bytes', async () => {
    const dns = createInMemoryDnsLookup({
      zone: { 'a.example.com': { txt: ['ééé'] } },
      bounds: { maxRecordLength: 5 }
    })
    await rejectsWith(dns.lookupTxt('a.example.com'), 'INVALID_RESPONSE')
  })
})

describe('DNS wire query', () => {
  const responseFor = (requestBuffer, overrides = {}) => {
    const request = dnsPacket.decode(requestBuffer)
    return dnsPacket.encode({
      type: 'response',
      id: request.id,
      flags: dnsPacket.RECURSION_AVAILABLE,
      questions: request.questions,
      answers: [],
      authorities: [],
      additionals: [],
      ...overrides
    })
  }

  it('sends a bounded query only to a configured resolver', async () => {
    const exchangeUdp = vi.fn((server, request) => {
      expect(server).toBe('192.0.2.53')
      expect(dnsPacket.decode(request).questions).toEqual([
        { name: 'a.example.com', type: 'TXT', class: 'IN' }
      ])
      return responseFor(request)
    })
    const query = createDnsWireQuery(
      { servers: ['192.0.2.53'], timeoutMillis: 100, tries: 1 },
      { nextId: () => 42, exchangeUdp }
    )
    await expect(query('a.example.com', 'TXT')).resolves.toMatchObject({ id: 42 })
    expect(exchangeUdp).toHaveBeenCalledOnce()
  })

  it('falls back to TCP for a matching truncated UDP response', async () => {
    const exchangeUdp = vi.fn((_server, request) =>
      responseFor(request, { flags: dnsPacket.TRUNCATED_RESPONSE })
    )
    const exchangeTcp = vi.fn((_server, request) =>
      dnsPacket.encode({
        type: 'response',
        id: request.id,
        flags: dnsPacket.RECURSION_AVAILABLE,
        questions: request.questions,
        answers: [],
        authorities: [],
        additionals: []
      })
    )
    const query = createDnsWireQuery(
      { servers: ['192.0.2.53'], timeoutMillis: 100, tries: 1 },
      { nextId: () => 42, exchangeUdp, exchangeTcp }
    )
    await expect(query('a.example.com', 'TXT')).resolves.toMatchObject({ flag_tc: false })
    expect(exchangeTcp).toHaveBeenCalledOnce()
  })

  it('rejects a response that does not match its transaction', async () => {
    const exchangeUdp = vi.fn((_server, request) =>
      responseFor(request, { id: 43, questions: [{ name: 'other.example.com', type: 'TXT' }] })
    )
    const query = createDnsWireQuery(
      { servers: ['192.0.2.53'], timeoutMillis: 100, tries: 1 },
      { nextId: () => 42, exchangeUdp }
    )
    await expect(query('a.example.com', 'TXT')).rejects.toMatchObject({ code: 'EBADRESP' })
  })

  it('bounds retries across the configured resolver list', async () => {
    const exchangeUdp = vi.fn().mockRejectedValue(
      Object.assign(new Error('timeout'), {
        code: 'ETIMEOUT'
      })
    )
    const query = createDnsWireQuery(
      { servers: ['192.0.2.53', '2001:db8::53'], timeoutMillis: 100, tries: 2 },
      { nextId: () => 42, exchangeUdp }
    )
    await expect(query('a.example.com', 'TXT')).rejects.toMatchObject({ code: 'ETIMEOUT' })
    expect(exchangeUdp).toHaveBeenCalledTimes(4)
  })
})

describe('node DNS adapter', () => {
  const options = { servers: ['192.0.2.53'], timeoutMillis: 100, tries: 1 }
  const response = ({ rcode = 'NOERROR', answers = [], authorities = [] } = {}) => ({
    rcode,
    answers,
    authorities
  })
  const soa = (ttl, minimum) => ({
    name: 'example.com',
    type: 'SOA',
    class: 'IN',
    ttl,
    data: {
      mname: 'ns.example.com',
      rname: 'hostmaster.example.com',
      serial: 1,
      refresh: 2,
      retry: 3,
      expire: 4,
      minimum
    }
  })

  it('requires an explicit resolver list of IP addresses', () => {
    expect(() => createNodeDnsLookup({})).toThrow()
    expect(() => createNodeDnsLookup({ servers: [] })).toThrow()
    expect(() => createNodeDnsLookup({ servers: ['dns.example.com'] })).toThrow()
  })

  it('joins TXT strings from direct owner records', async () => {
    const queryDns = vi.fn().mockResolvedValue(
      response({
        answers: [
          {
            name: '_f0.example.com',
            type: 'TXT',
            class: 'IN',
            data: [Buffer.from('f0-verify='), Buffer.from('abc')]
          },
          {
            name: '_f0.example.com.',
            type: 'TXT',
            class: 'IN',
            data: [Buffer.from('other')]
          }
        ]
      })
    )
    const dns = createNodeDnsLookup(options, { queryDns })
    expect(await dns.lookupTxt('_f0.example.com')).toEqual(['f0-verify=abc', 'other'])
    expect(queryDns).toHaveBeenCalledWith('_f0.example.com', 'TXT')
  })

  it.each([
    ['ETIMEOUT', 'TIMEOUT'],
    ['ESERVFAIL', 'SERVFAIL'],
    ['ECONNREFUSED', 'SERVFAIL'],
    ['EREFUSED', 'SERVFAIL'],
    ['EBADRESP', 'INVALID_RESPONSE']
  ])('maps wire query error %s to %s', async (wireCode, code) => {
    const queryDns = vi.fn().mockRejectedValue(Object.assign(new Error('x'), { code: wireCode }))
    await rejectsWith(createNodeDnsLookup(options, { queryDns }).lookupTxt('a.example.com'), code)
  })

  it.each(['SERVFAIL', 'REFUSED', 'NOTIMP'])('maps DNS %s to retryable SERVFAIL', async (rcode) => {
    const queryDns = vi.fn().mockResolvedValue(response({ rcode }))
    const error = await rejectsWith(
      createNodeDnsLookup(options, { queryDns }).lookupTxt('a.example.com'),
      'SERVFAIL'
    )
    expect(error.retryable).toBe(true)
  })

  it('derives NXDOMAIN and NODATA delays from the response SOA', async () => {
    const nxdomain = createNodeDnsLookup(options, {
      queryDns: vi
        .fn()
        .mockResolvedValue(response({ rcode: 'NXDOMAIN', authorities: [soa(600, 120)] }))
    })
    expect(
      (await rejectsWith(nxdomain.lookupTxt('a.example.com'), 'NXDOMAIN')).retryAfterSeconds
    ).toBe(120)

    const noData = createNodeDnsLookup(options, {
      queryDns: vi.fn().mockResolvedValue(response({ authorities: [soa(30, 300)] }))
    })
    expect((await rejectsWith(noData.lookupTxt('a.example.com'), 'NODATA')).retryAfterSeconds).toBe(
      30
    )
  })

  it('uses the fallback for absent or malformed negative SOA metadata', async () => {
    for (const authorities of [[], [soa(-1, 30)], [soa(30, 'bad')]]) {
      const dns = createNodeDnsLookup(options, {
        queryDns: vi.fn().mockResolvedValue(response({ rcode: 'NXDOMAIN', authorities }))
      })
      expect(
        (await rejectsWith(dns.lookupTxt('a.example.com'), 'NXDOMAIN')).retryAfterSeconds
      ).toBe(60)
    }
  })

  it('keeps zero and caps excessive negative-cache delays', async () => {
    const delayFor = async (authority) => {
      const dns = createNodeDnsLookup(options, {
        queryDns: vi
          .fn()
          .mockResolvedValue(response({ rcode: 'NXDOMAIN', authorities: [authority] }))
      })
      return (await rejectsWith(dns.lookupTxt('a.example.com'), 'NXDOMAIN')).retryAfterSeconds
    }
    expect(await delayFor(soa(0, 300))).toBe(0)
    expect(await delayFor(soa(7200, 8000))).toBe(3600)
  })

  it('lets unknown implementation errors through', async () => {
    const boom = new TypeError('bug')
    const queryDns = vi.fn().mockRejectedValue(boom)
    await expect(
      createNodeDnsLookup(options, { queryDns }).lookupTxt('a.example.com')
    ).rejects.toBe(boom)
  })

  it('rejects malformed and oversized answers', async () => {
    const answer = (value) =>
      createNodeDnsLookup(
        { ...options, maxRecords: 1, maxRecordLength: 8 },
        { queryDns: vi.fn().mockResolvedValue(value) }
      ).lookupTxt('a.example.com')
    await rejectsWith(answer('not-an-array'), 'INVALID_RESPONSE')
    await rejectsWith(
      answer(
        response({
          answers: [{ name: 'a.example.com', type: 'TXT', class: 'IN', data: [1] }]
        })
      ),
      'INVALID_RESPONSE'
    )
    await rejectsWith(
      answer(
        response({
          answers: ['a', 'b'].map((value) => ({
            name: 'a.example.com',
            type: 'TXT',
            class: 'IN',
            data: [Buffer.from(value)]
          }))
        })
      ),
      'INVALID_RESPONSE'
    )
    await rejectsWith(
      answer(
        response({
          answers: [
            {
              name: 'a.example.com',
              type: 'TXT',
              class: 'IN',
              data: [Buffer.from('x'.repeat(9))]
            }
          ]
        })
      ),
      'INVALID_RESPONSE'
    )
  })

  it('traverses CNAME targets and never queries an invalid name', async () => {
    const queryDns = vi.fn(async (host) => {
      if (host === 'a.example.com') {
        return response({
          answers: [{ name: host, type: 'CNAME', class: 'IN', data: 'TARGET.EXAMPLE.NET.' }]
        })
      }
      return response({ authorities: [soa(60, 60)] })
    })
    const dns = createNodeDnsLookup(options, { queryDns })
    expect(await dns.lookupCname('a.example.com')).toEqual(['target.example.net'])
    expect(queryDns).toHaveBeenNthCalledWith(1, 'a.example.com', 'CNAME')
    expect(queryDns).toHaveBeenNthCalledWith(2, 'target.example.net', 'CNAME')
    await rejectsWith(dns.lookupCname('Bad Name'), 'INVALID_NAME')
    expect(queryDns).toHaveBeenCalledTimes(2)
  })

  it('detects a CNAME loop across wire queries', async () => {
    const queryDns = vi.fn(async (host) => {
      const target = host === 'a.example.com' ? 'b.example.com' : 'a.example.com'
      return response({
        answers: [{ name: host, type: 'CNAME', class: 'IN', data: target }]
      })
    })
    const error = await rejectsWith(
      createNodeDnsLookup(options, { queryDns }).lookupCname('a.example.com'),
      'CNAME_LOOP'
    )
    expect(error.retryable).toBe(false)
  })
})
