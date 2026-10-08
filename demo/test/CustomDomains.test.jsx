import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, test, vi } from 'vitest'
import { CustomDomains } from '../src/CustomDomains.jsx'

const pending = {
  id: '4a4d4ba1-3366-4f23-beb0-3cc41a58c001',
  host: 'xn--bcher-kva.example.com',
  displayHost: 'bücher.example.com',
  state: 'pending',
  challengeExpiresAt: '2026-10-04T12:00:00.000Z',
  lastCheckedAt: null,
  verifiedAt: null,
  lastFailureReason: null,
  createdAt: '2026-10-03T12:00:00.000Z',
  updatedAt: '2026-10-03T12:00:00.000Z'
}

const challenge = {
  recordName: '_f0-challenge.login.example.com',
  recordType: 'TXT',
  recordValue: 'f0-domain-verification=one-time-value',
  expiresAt: '2026-10-04T12:00:00.000Z'
}

function client(overrides = {}) {
  return {
    list: vi.fn(async () => [pending]),
    add: vi.fn(),
    check: vi.fn(),
    reissue: vi.fn(),
    remove: vi.fn(),
    ...overrides
  }
}

describe('custom domains screen', () => {
  test('keeps capacity and add controls unresolved while the list loads', () => {
    render(<CustomDomains client={client({ list: vi.fn(() => new Promise(() => {})) })} />)

    expect(screen.getByLabelText('Domain capacity loading')).toHaveTextContent('—/10 domains')
    expect(screen.getByLabelText('Host')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Add domain' })).toBeDisabled()
    expect(screen.getByLabelText('Loading custom domains')).toBeVisible()
  })

  test('shows the canonical host, unavailable one-time value, status, and recovery action', async () => {
    render(<CustomDomains client={client()} />)

    expect(await screen.findByRole('heading', { name: 'bücher.example.com' })).toBeVisible()
    expect(screen.getByText('xn--bcher-kva.example.com')).toBeVisible()
    expect(screen.getByText('Awaiting DNS')).toBeVisible()
    expect(screen.getByText('TXT value is no longer available')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Reissue challenge' })).toBeEnabled()
  })

  test('adds a host and keeps the returned TXT challenge available for copying', async () => {
    const added = {
      ...pending,
      id: 'new-id',
      host: 'login.example.com',
      displayHost: 'login.example.com'
    }
    const api = client({
      list: vi.fn(async () => []),
      add: vi.fn(async () => ({ domain: added, challenge }))
    })
    const user = userEvent.setup()
    const writeText = vi.spyOn(navigator.clipboard, 'writeText')
    render(<CustomDomains client={api} />)

    await screen.findByText('No custom domains yet')
    await user.type(screen.getByLabelText('Host'), 'login.example.com')
    await user.click(screen.getByRole('button', { name: 'Add domain' }))

    expect(await screen.findByText('Shown once')).toBeVisible()
    expect(screen.getByText('f0-domain-verification=one-time-value')).toBeVisible()
    await user.click(screen.getByRole('button', { name: 'Copy value' }))
    expect(writeText).toHaveBeenCalledWith('f0-domain-verification=one-time-value')
    expect(api.add).toHaveBeenCalledWith('login.example.com')
  })

  test('checks ownership and stops at verified rather than implying serving readiness', async () => {
    const verified = {
      ...pending,
      state: 'verified',
      verifiedAt: '2026-10-03T12:00:00.000Z',
      lastCheckedAt: '2026-10-03T12:00:00.000Z'
    }
    const api = client({
      check: vi.fn(async () => ({ verified: true, retryable: false, domain: verified }))
    })
    const user = userEvent.setup()
    render(<CustomDomains client={api} />)

    await user.click(await screen.findByRole('button', { name: 'Check now' }))

    expect(await screen.findByText('Ownership verified')).toBeVisible()
    expect(screen.getByRole('status')).toHaveTextContent('Serving readiness is managed separately')
  })

  test('requires confirmation before removal', async () => {
    const api = client({ remove: vi.fn(async () => undefined) })
    const user = userEvent.setup()
    render(<CustomDomains client={api} />)

    await user.click(await screen.findByRole('button', { name: 'Remove bücher.example.com' }))
    expect(screen.getByRole('dialog')).toHaveTextContent('Remove bücher.example.com?')
    expect(api.remove).not.toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: 'Remove domain' }))
    await waitFor(() => expect(api.remove).toHaveBeenCalledWith(pending.id))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.getByText('No custom domains yet')).toBeVisible()
  })

  test('makes request failure and the ten-domain limit actionable', async () => {
    const failing = client({ list: vi.fn(async () => Promise.reject({ status: 503 })) })
    const { rerender } = render(<CustomDomains client={failing} />)
    expect(await screen.findByRole('status')).toHaveTextContent('temporarily unavailable')
    expect(screen.getByRole('button', { name: 'Try again' })).toBeVisible()

    const full = Array.from({ length: 10 }, (_, index) => ({
      ...pending,
      id: `domain-${index}`,
      host: `login-${index}.example.com`,
      displayHost: `login-${index}.example.com`,
      state: 'verified'
    }))
    rerender(<CustomDomains client={client({ list: vi.fn(async () => full) })} />)

    expect(await screen.findByLabelText('10 of 10 domains used')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Add domain' })).toBeDisabled()
    expect(screen.getByText('Remove a domain before adding another.')).toBeVisible()
  })
})
