import { randomInt } from 'node:crypto'
import { createSocket } from 'node:dgram'
import { createConnection } from 'node:net'
import dnsPacket from 'dns-packet'

const DNS_PORT = 53
const MAX_TCP_MESSAGE_BYTES = 65535

function timeoutError() {
  return Object.assign(new Error('DNS query timed out'), { code: 'ETIMEOUT' })
}

function invalidResponse(message, cause) {
  return Object.assign(new Error(message, cause ? { cause } : undefined), { code: 'EBADRESP' })
}

function udpExchange(server, request, timeoutMillis) {
  return new Promise((resolve, reject) => {
    const socket = createSocket(server.includes(':') ? 'udp6' : 'udp4')
    let settled = false
    const finish = (error, response) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.close()
      if (error) reject(error)
      else resolve(response)
    }
    const timer = setTimeout(() => finish(timeoutError()), timeoutMillis)
    socket.once('error', (error) => finish(error))
    socket.once('message', (response) => finish(null, response))
    socket.connect(DNS_PORT, server, () => socket.send(request))
  })
}

function tcpExchange(server, request, timeoutMillis) {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: server, port: DNS_PORT })
    const chunks = []
    let receivedBytes = 0
    let expectedBytes
    let settled = false
    const finish = (error, response) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.destroy()
      if (error) reject(error)
      else resolve(response)
    }
    const timer = setTimeout(() => finish(timeoutError()), timeoutMillis)
    socket.once('error', (error) => finish(error))
    socket.on('data', (chunk) => {
      chunks.push(chunk)
      receivedBytes += chunk.length
      if (receivedBytes >= 2 && expectedBytes === undefined) {
        const prefix = Buffer.concat(chunks, receivedBytes)
        expectedBytes = prefix.readUInt16BE(0)
        if (expectedBytes > MAX_TCP_MESSAGE_BYTES) {
          finish(invalidResponse('DNS TCP response is too large'))
          return
        }
      }
      if (expectedBytes !== undefined && receivedBytes >= expectedBytes + 2) {
        const framed = Buffer.concat(chunks, receivedBytes)
        if (receivedBytes !== expectedBytes + 2) {
          finish(invalidResponse('DNS TCP response has trailing data'))
          return
        }
        finish(null, framed.subarray(2))
      }
    })
    socket.once('end', () => {
      if (!settled) finish(invalidResponse('DNS TCP response ended early'))
    })
    socket.once('connect', () => socket.write(dnsPacket.streamEncode(request)))
  })
}

function sameQuestion(actual, expected) {
  if (!actual || actual.type !== expected.type || actual.class !== 'IN') return false
  const name = actual.name.endsWith('.') ? actual.name.slice(0, -1) : actual.name
  return name.toLowerCase() === expected.name
}

function decodeResponse(buffer, id, question) {
  let response
  try {
    response = dnsPacket.decode(buffer)
  } catch (error) {
    throw invalidResponse('Malformed DNS response', error)
  }
  if (
    response.type !== 'response' ||
    response.id !== id ||
    response.opcode !== 'QUERY' ||
    response.questions.length !== 1 ||
    !sameQuestion(response.questions[0], question)
  ) {
    throw invalidResponse('DNS response does not match the query')
  }
  return response
}

/** Queries configured recursive resolvers, retrying UDP and falling back to TCP when truncated. */
export function createDnsWireQuery(
  { servers, timeoutMillis, tries },
  { nextId = () => randomInt(0x10000), exchangeUdp = udpExchange, exchangeTcp = tcpExchange } = {}
) {
  return async (host, type) => {
    const id = nextId()
    const question = { type, class: 'IN', name: host }
    const request = {
      type: 'query',
      id,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [question]
    }
    const encoded = dnsPacket.encode(request)
    let lastError

    for (let attempt = 0; attempt < tries; attempt += 1) {
      for (const server of servers) {
        try {
          const udpResponse = decodeResponse(
            await exchangeUdp(server, encoded, timeoutMillis),
            id,
            question
          )
          if (!udpResponse.flag_tc) return udpResponse
          return decodeResponse(await exchangeTcp(server, request, timeoutMillis), id, question)
        } catch (error) {
          lastError = error
        }
      }
    }
    throw lastError
  }
}
