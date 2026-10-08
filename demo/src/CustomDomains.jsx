import { useEffect, useState } from 'react'

const STATUS = {
  pending: { label: 'Awaiting DNS', tone: 'waiting' },
  verified: { label: 'Ownership verified', tone: 'success' },
  active: { label: 'Active', tone: 'success' },
  verification_lost: { label: 'Verification lost', tone: 'danger' },
  failed: { label: 'Check failed', tone: 'danger' }
}

const FAILURE_MESSAGES = {
  'dns-nxdomain':
    'TXT record not found. Add it at your DNS provider, then allow time for propagation and negative caches to expire.',
  'txt-record-mismatch':
    'The TXT record has the wrong value. Replace it with the exact challenge value.',
  'dns-servfail':
    'The DNS resolver could not complete the lookup. Try again after your DNS provider recovers.',
  'challenge-expired': 'The challenge expired. Reissue it to receive a new TXT value.'
}

export function CustomDomains({ client }) {
  const [domains, setDomains] = useState([])
  const [challenges, setChallenges] = useState({})
  const [phase, setPhase] = useState('loading')
  const [message, setMessage] = useState(null)
  const [busy, setBusy] = useState(null)
  const [removing, setRemoving] = useState(null)

  const load = async () => {
    setPhase('loading')
    setMessage(null)
    try {
      setDomains(await client.list())
      setPhase('ready')
    } catch (error) {
      setMessage(errorMessage(error, 'load'))
      setPhase('error')
    }
  }

  useEffect(() => {
    load()
  }, [client])

  const updateDomain = (next) =>
    setDomains((current) => current.map((item) => (item.id === next.id ? next : item)))

  async function add(event) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const host = form.get('host').trim()
    if (!host) {
      setMessage('Enter a host such as login.example.com.')
      return
    }
    setBusy('add')
    setMessage(null)
    try {
      const result = await client.add(host)
      setDomains((current) => [result.domain, ...current])
      setChallenges((current) => ({ ...current, [result.domain.id]: result.challenge }))
      event.currentTarget.reset()
    } catch (error) {
      setMessage(errorMessage(error, 'add'))
    } finally {
      setBusy(null)
    }
  }

  async function check(item) {
    setBusy(`check:${item.id}`)
    setMessage(null)
    try {
      const result = await client.check(item.id)
      updateDomain(result.domain)
      setMessage(
        result.verified
          ? `Ownership of ${item.displayHost} is verified. Serving readiness is managed separately.`
          : failureMessage(result.reason)
      )
    } catch (error) {
      setMessage(errorMessage(error, 'check'))
    } finally {
      setBusy(null)
    }
  }

  async function reissue(item) {
    setBusy(`reissue:${item.id}`)
    setMessage(null)
    try {
      const result = await client.reissue(item.id)
      updateDomain(result.domain)
      setChallenges((current) => ({ ...current, [item.id]: result.challenge }))
    } catch (error) {
      setMessage(errorMessage(error, 'reissue'))
    } finally {
      setBusy(null)
    }
  }

  async function remove() {
    const item = removing
    setBusy(`remove:${item.id}`)
    setMessage(null)
    try {
      await client.remove(item.id)
      setDomains((current) => current.filter((candidate) => candidate.id !== item.id))
      setChallenges((current) => {
        const next = { ...current }
        delete next[item.id]
        return next
      })
      setRemoving(null)
    } catch (error) {
      setMessage(errorMessage(error, 'remove'))
    } finally {
      setBusy(null)
    }
  }

  const atLimit = domains.length >= 10
  const addDisabled = phase !== 'ready' || atLimit || busy === 'add'

  return (
    <main>
      <div className="eyebrow">Identity provider</div>
      <div className="page-heading">
        <div>
          <h1>Custom domains</h1>
          <p>Prove ownership of the hosts your users will recognize.</p>
        </div>
        <span
          className="capacity"
          aria-label={
            phase === 'loading' ? 'Domain capacity loading' : `${domains.length} of 10 domains used`
          }
        >
          {phase === 'loading' ? '—' : domains.length}
          <i>/</i>10 domains
        </span>
      </div>

      <section className="settings-card add-card" aria-labelledby="add-heading">
        <div>
          <h2 id="add-heading">Add a domain</h2>
          <p>Use a full host name. You’ll publish one TXT record to prove ownership.</p>
        </div>
        <form onSubmit={add}>
          <label htmlFor="host">Host</label>
          <div className="add-row">
            <input
              id="host"
              name="host"
              type="text"
              placeholder="login.example.com"
              autoComplete="off"
              disabled={addDisabled}
            />
            <button className="primary" disabled={addDisabled}>
              {busy === 'add' ? 'Adding…' : 'Add domain'}
            </button>
          </div>
          {atLimit && <p className="field-note">Remove a domain before adding another.</p>}
        </form>
      </section>

      {message && (
        <div className="notice" role="status">
          <span>{message}</span>
          {phase === 'error' && <button onClick={load}>Try again</button>}
        </div>
      )}

      <section className="domain-list" aria-label="Custom domains">
        {phase === 'loading' ? (
          <LoadingState />
        ) : phase === 'ready' && domains.length === 0 ? (
          <EmptyState />
        ) : (
          domains.map((item) => (
            <DomainCard
              key={item.id}
              item={item}
              challenge={challenges[item.id]}
              busy={busy}
              onCheck={() => check(item)}
              onReissue={() => reissue(item)}
              onRemove={() => setRemoving(item)}
            />
          ))
        )}
      </section>

      {removing && (
        <div className="dialog-backdrop" role="presentation">
          <div className="dialog" role="dialog" aria-modal="true" aria-labelledby="remove-title">
            <div className="warning-mark">!</div>
            <h2 id="remove-title">Remove {removing.displayHost}?</h2>
            <p>
              F0 will stop tracking this domain. Remove its ownership TXT record from your DNS
              provider afterward.
            </p>
            <div className="dialog-actions">
              <button onClick={() => setRemoving(null)}>Cancel</button>
              <button className="danger" onClick={remove} disabled={busy?.startsWith('remove:')}>
                {busy?.startsWith('remove:') ? 'Removing…' : 'Remove domain'}
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  )
}

function DomainCard({ item, challenge, busy, onCheck, onReissue, onRemove }) {
  const status = STATUS[item.state]
  const unavailable = !challenge && ['pending', 'verification_lost', 'failed'].includes(item.state)

  return (
    <article className="settings-card domain-card">
      <header className="domain-header">
        <div className="domain-identity">
          <div className="domain-glyph" aria-hidden="true">
            ◇
          </div>
          <div>
            <h2>{item.displayHost}</h2>
            {item.displayHost !== item.host && <code className="canonical">{item.host}</code>}
          </div>
        </div>
        <span className={`badge ${status.tone}`}>
          <i /> {status.label}
        </span>
      </header>

      {item.lastFailureReason && (
        <div className="failure">
          <strong>Last check needs attention</strong>
          <span>{failureMessage(item.lastFailureReason)}</span>
        </div>
      )}

      {challenge ? (
        <Challenge challenge={challenge} />
      ) : unavailable ? (
        <div className="challenge-unavailable">
          <div>
            <strong>TXT value is no longer available</strong>
            <p>For security, the TXT value is never returned again. Reissue to replace it.</p>
          </div>
          <button onClick={onReissue} disabled={busy === `reissue:${item.id}`}>
            {busy === `reissue:${item.id}` ? 'Reissuing…' : 'Reissue challenge'}
          </button>
        </div>
      ) : (
        <div className="verified-note">
          Ownership is established. Serving readiness is separate.
        </div>
      )}

      <footer className="domain-actions">
        <span>
          {item.lastCheckedAt
            ? `Last checked ${formatDate(item.lastCheckedAt)}`
            : 'Not checked yet'}
        </span>
        <div>
          <button onClick={onCheck} disabled={busy === `check:${item.id}`}>
            {busy === `check:${item.id}` ? 'Checking…' : 'Check now'}
          </button>
          <button
            className="remove-button"
            onClick={onRemove}
            aria-label={`Remove ${item.displayHost}`}
          >
            Remove
          </button>
        </div>
      </footer>
    </article>
  )
}

function Challenge({ challenge }) {
  return (
    <div className="challenge">
      <div className="challenge-intro">
        <div>
          <span className="step">1</span>
          <strong>Add this record at your DNS provider</strong>
        </div>
        <span className="one-time">Shown once</span>
      </div>
      <p>Copy both fields now. The TXT value cannot be recovered after you leave or refresh.</p>
      <RecordRow label="Name" value={challenge.recordName} />
      <RecordRow label="Value" value={challenge.recordValue} />
      <div className="challenge-expiry">Expires {formatDate(challenge.expiresAt)}</div>
    </div>
  )
}

function RecordRow({ label, value }) {
  const [copied, setCopied] = useState(false)

  async function copy() {
    await navigator.clipboard.writeText(value)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1200)
  }

  return (
    <div className="record-row">
      <span>{label}</span>
      <code>{value}</code>
      <button onClick={copy} aria-label={`Copy ${label.toLowerCase()}`}>
        {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
  )
}

function LoadingState() {
  return (
    <div className="settings-card loading-state" aria-label="Loading custom domains">
      <div className="skeleton wide" />
      <div className="skeleton narrow" />
      <div className="skeleton block" />
    </div>
  )
}

function EmptyState() {
  return (
    <div className="settings-card empty-state">
      <div className="empty-glyph">◇</div>
      <h2>No custom domains yet</h2>
      <p>Add a host above to get its one-time DNS ownership challenge.</p>
    </div>
  )
}

function failureMessage(reason) {
  return (
    FAILURE_MESSAGES[reason] ??
    `Verification failed (${reason}). Review the TXT record and try again.`
  )
}

function errorMessage(error, action) {
  if (error.code === 'invalid_host')
    return 'Enter a valid host name without a protocol, path, port, wildcard, or IP address.'
  if (error.code === 'host_taken') return 'That host is already attached to this identity provider.'
  if (error.code === 'domain_limit_reached')
    return 'This identity provider already has its maximum of 10 domains.'
  if (error.code === 'rate_limited')
    return `You checked too recently. Try again in ${error.retryAfter ?? '60'} seconds.`
  if (error.status === 503 && action === 'check')
    return 'Verification checks are unavailable because no DNS resolver is configured.'
  if (error.status === 503) return 'Custom domains are temporarily unavailable. Try again.'
  if (error.status === 404) return 'This domain no longer exists. Refresh the list.'
  return `Could not ${action} custom domains. Try again.`
}

function formatDate(value) {
  return new Intl.DateTimeFormat('en', {
    day: 'numeric',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
    timeZone: 'UTC',
    timeZoneName: 'short'
  }).format(new Date(value))
}
