# Threat model domain takeover and custom domain abuse (F0-122)

Status: evidence review for coordinator triage. This document records source observations,
preconditions, impact, and proposed follow-up text. It does not approve policy, architecture,
ownership, trust-boundary, persistence, runtime-topology, or public-contract changes, and it does
not assign people.

The review snapshot is [`origin/main` at
`9d589413`](https://github.com/big-kahuna-burger/f0tesla/commit/9d58941335942208362de13f56566780f5298b6c)
on 2026-10-01. The [F0-122 Linear issue](https://linear.app/fid/issue/F0-122/threat-model-domain-takeover-and-custom-domain-abuse)
had no relations, attachments, documents, or customer needs at review time. The broader
[architecture threat-model draft](../architecture/custom-domain-threat-model.md) supplies design
context, but its recommendations remain proposals and some of its branch-status statements predate
this snapshot. This review uses current source as evidence.

Later change: in-process tenancy has since been retired. Tenants, memberships and tenant ownership
of custom domains no longer exist in the identity provider; a domain belongs to the process that
holds it, and the limit of 10 applies to that process. Statements below that scope a domain, a
challenge, a read or a quota to a tenant describe the model as reviewed at the snapshot above, and
read as the whole process today. Running separate sets of domains apart means running separate
identity providers.

## Review boundary and confidence

Implemented components are not an end-to-end custom-domain product. Main contains domain
normalization, persistence, a DNS adapter, and an injected challenge library, but application
composition only creates the repository; there is no custom-domain management route, scheduler,
UI, check-now endpoint, custom-host router, certificate/controller integration, or branded-login
serving path. The current request path still pins OIDC requests to one configured issuer and removes
forwarded-host input ([composition](../../apps/identity-provider/application.js#L71-L93),
[canonical-origin pinning](../../apps/identity-provider/application.js#L202-L225),
[header rewrite](../../apps/identity-provider/application.js#L261-L270)).

Therefore:

- **Implemented defense** means the cited component enforces or represents the behavior when that
  component is called. It is not evidence that a production request reaches it.
- **Confirmed gap** means current source has a security-relevant omission or unsafe property that
  downstream work must resolve before exposure.
- **Future flow** means the attack surface does not exist on main. Its acceptance must be reviewed
  when the management, scheduling, routing, certificate, controller, or UI flow lands.

This is not a general-availability sign-off. End-to-end abuse review remains incomplete until the
future flows exist and their controls have executable acceptance evidence.

## Implemented defenses observed on main

| Area                                            | Source evidence                                                                                                                                                                                                                                                                                                                                   | What is actually defended                                                                                                                                                                                                                                                 |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Domain canonicalization                         | [`custom-domain-name.js`](../../apps/identity-provider/management/custom-domain-name.js#L76-L125)                                                                                                                                                                                                                                                 | UTS #46 processing produces an A-label for storage and U-label for display; malformed names, wildcard names, IP literals, ports, paths, public/special-use suffixes, the platform host and its children, and labels containing more than one Unicode script are rejected. |
| Challenge construction                          | [`verification.js`](../../apps/custom-domain-verification/verification.js#L18-L54), [`verification.js`](../../apps/custom-domain-verification/verification.js#L141-L170)                                                                                                                                                                          | Default entropy is 256 bits with a 128-bit minimum. The seven-day challenge is hashed with tenant and normalized host before storage, compared in constant time, and plaintext is returned only by issue/reissue results.                                                 |
| Exact DNS proof                                 | [`verification.js`](../../apps/custom-domain-verification/verification.js#L57-L114)                                                                                                                                                                                                                                                               | The exact `_f0-challenge.<host>` owner is checked for CNAME first; any CNAME is refused. An exact TXT value is required, and time is sampled after DNS awaits.                                                                                                            |
| Atomic verification                             | [`custom-domain-repository.js`](../../apps/identity-provider/persistence/custom-domain-repository.js#L83-L111)                                                                                                                                                                                                                                    | The final transition locks the row and rechecks tenant, row, pending state, challenge hash, and expiry against PostgreSQL `clock_timestamp()`.                                                                                                                            |
| Tenant isolation and live-host uniqueness       | [`custom-domain-repository.js`](../../apps/identity-provider/persistence/custom-domain-repository.js#L23-L38), [`schema.js`](../../apps/identity-provider/persistence/schema.js#L317-L337)                                                                                                                                                        | Reads are tenant-scoped. A partial unique index permits only one non-removed row for a normalized host across all tenants.                                                                                                                                                |
| Fresh proof after removal                       | [`verification.test.js`](../../apps/custom-domain-verification/verification.test.js#L229-L287), [`custom-domain-repository.test.js`](../../apps/identity-provider/test/integration/persistence/custom-domain-repository.test.js#L73-L89)                                                                                                          | The component tests encode token rotation, tenant/domain binding, release of uniqueness on removal, and rejection of the previous tenant's TXT proof for a new tenant. These are inspected tests, not a test run performed by this documentation review.                  |
| Bounded resolver work                           | [`dns-lookup.js`](../../apps/identity-provider/management/dns-lookup.js#L16-L23), [`dns-lookup.js`](../../apps/identity-provider/management/dns-lookup.js#L48-L77), [`dns-lookup.js`](../../apps/identity-provider/management/dns-lookup.js#L93-L150), [`node-dns-lookup.js`](../../apps/identity-provider/management/node-dns-lookup.js#L13-L20) | DNS names, answer count, record size, CNAME count/loops, resolver count, timeout, and tries are bounded. Resolver targets must be configured IP addresses, not tenant input.                                                                                              |
| Minimal current token persistence/audit surface | [`schema.js`](../../apps/identity-provider/persistence/schema.js#L317-L330), [`security/audit.js`](../../apps/identity-provider/security/audit.js#L70-L123)                                                                                                                                                                                       | Persistence has only `challengeHash`, not plaintext. Generic management audit records compact route metadata rather than request/response bodies. No custom-domain route or event exists yet, so this does not establish future API/UI/log safety.                        |

## Findings

### F1 — Lapse/removal takeover controls are not implemented

**Classification:** confirmed gap in lifecycle; future serving flow. **Severity if custom-host serving
is enabled without it:** high.

**Evidence.** The state vocabulary includes `active`, `verification_lost`, and `removed`, but the
repository exposes only a generic tenant-scoped transition and the challenge service checks only
`pending` rows ([states](../../apps/custom-domain-verification/repository.js#L1-L17),
[check gate](../../apps/custom-domain-verification/verification.js#L57-L67),
[transition](../../apps/identity-provider/persistence/custom-domain-repository.js#L114-L127)). There
is no scheduler, maximum proof age, periodic active-domain check, serving inhibit, removal
orchestrator, route/certificate withdrawal, or ownership-generation fence on main. F0-116,
F0-119, and F0-120 describe some future behavior, but none is current enforcement.

**Abuse preconditions.** A future custom host has been activated; the tenant loses registration or
DNS control, abandons a routing CNAME target, or removes the host; a stale application cache,
controller snapshot, route, certificate, or worker action still treats the old ownership as valid.

**Impact.** The new DNS owner or a party claiming a dangling routing target could receive traffic,
present a login surface, or race stale control-plane work. Removing a database row's serving status
would not by itself revoke an already-issued certificate or prove ingress withdrawal.

**Suggested mitigation, not adopted.** Make request eligibility depend on fresh ownership proof and
an independent serving-inhibit state; define a bounded loss-to-denial objective; withdraw routes and
certificate reconciliation on loss/removal; require current proof before restoration; and fence
every asynchronous action with an ownership generation. The owner must choose availability behavior
during DNS and controller outages and the maximum acceptable takeover window.

### F2 — Global uniqueness prevents dual live claims but enables pending-claim denial of service

**Classification:** implemented integrity defense with a confirmed availability gap. **Severity once
the add API is reachable:** medium.

**Evidence.** The unique index covers every state except `removed`, including an expired `pending`
row ([schema](../../apps/identity-provider/persistence/schema.js#L332-L336)). A challenge expires
after seven days, but an expiry check only records a failure; it does not mark the row `failed`,
`removed`, or release uniqueness ([expiry handling](../../apps/custom-domain-verification/verification.js#L64-L67),
[failure persistence](../../apps/custom-domain-verification/verification.js#L123-L135)). The
database tests confirm that another tenant is blocked until the first row is explicitly removed
([integration evidence](../../apps/identity-provider/test/integration/persistence/custom-domain-repository.test.js#L73-L89)).

**Abuse preconditions.** A hostile tenant can call the future add endpoint before the legitimate
tenant and can leave the challenge unproved. Repeating the claim depends on whatever cleanup,
re-add, and rate policies are later exposed.

**Impact.** Legitimate onboarding or transfer is denied even though the hostile tenant never proves
DNS control. Conversely, simply relaxing uniqueness would create competing proof and stale-job races.

**Suggested mitigation, not adopted.** The coordinator should present two explicit choices for owner
confirmation: retain reservation-on-add with automatic bounded pending expiry and anti-churn limits,
or change to first-valid-proof-wins with an atomic winner transaction, non-enumerating conflict
responses, and ownership-generation fencing. This is a persistence and claim-policy decision; the
review does not select one.

### F3 — IDN handling blocks mixed-script labels, not brand impersonation

**Classification:** implemented syntax defense with a confirmed policy gap; future branded-login
flow. **Severity if arbitrary custom hosts serve login pages:** high.

**Evidence.** A label is rejected only when its non-common Unicode characters span more than one
script ([script check](../../apps/identity-provider/management/custom-domain-name.js#L52-L65),
[normalization](../../apps/identity-provider/management/custom-domain-name.js#L89-L125)). Tests
explicitly accept a single-script Cyrillic label and reject a mixed Cyrillic/Latin label
([test evidence](../../apps/identity-provider/test/management/custom-domain-name.test.js#L22-L27),
[test evidence](../../apps/identity-provider/test/management/custom-domain-name.test.js#L67-L71)).
There is no confusable-skeleton comparison, protected-brand list, ASCII typosquat check, exception
process, or abuse response flow. F0-118 plans A-label/U-label display, which improves operator
visibility but does not determine legitimacy.

**Abuse preconditions.** A tenant controls a single-script IDN or ASCII look-alike and future routing
serves a valid TLS login page there. The victim relies on visual brand recognition rather than the
browser's exact host display.

**Impact.** Credential phishing and reputational harm can occur with valid DNS ownership and TLS;
DNS verification cannot distinguish legitimate delegation from malicious intent.

**Suggested mitigation, not adopted.** Decide whether launch posture is reactive abuse handling,
protected-brand screening with an exception process, or pre-activation review. Any deny-list needs a
maintainer role, appeal/false-positive process, and documented limitations; it must not be described
as proof of tenant legitimacy.

### F4 — Resolver bounds do not provide answer authenticity

**Classification:** implemented availability/input bounds with a confirmed DNS-integrity gap.
**Severity once verification is reachable:** high where the resolver path is untrusted.

**Evidence.** Main uses explicitly configured resolver IPs and bounded `node:dns` calls, but the
adapter explicitly does not cover DNSSEC status, DoH, or DoT
([adapter contract](../../apps/identity-provider/management/node-dns-lookup.js#L46-L52)). DNS-only
verification does not fetch from a tenant-controlled HTTP address, so classic DNS-rebinding SSRF is
not present on main. A forged TXT answer on the resolver path can still satisfy ownership proof.

[Open PR #257](https://github.com/big-kahuna-burger/f0tesla/pull/257) at
[`8ec16f9`](https://github.com/big-kahuna-burger/f0tesla/commit/8ec16f94b9fa1aee67f881474535bedc7f7dafe7)
is **unmerged evidence only**. It proposes query/response ID and question matching plus bounded UDP
with TCP fallback ([wire-query proposal](https://github.com/big-kahuna-burger/f0tesla/blob/8ec16f94b9fa1aee67f881474535bedc7f7dafe7/apps/identity-provider/management/dns-wire-query.js#L80-L138))
and RFC 2308 retry metadata ([adapter proposal](https://github.com/big-kahuna-burger/f0tesla/blob/8ec16f94b9fa1aee67f881474535bedc7f7dafe7/apps/identity-provider/management/node-dns-lookup.js#L124-L170)).
It still uses plaintext UDP/TCP port 53 and does not authenticate the resolver path. It must not be
reported as merged or as closing F0-138.

**Abuse preconditions.** An attacker can influence the configured recursive resolver, its network
path, cache, or an upstream response during a verification lookup.

**Impact.** False proof can bind an attacker-controlled tenant to a victim domain. DNSSEC's AD bit,
if later exposed, is only the trusted resolver's assertion unless the application validates the
chain itself.

**Suggested mitigation, not adopted.** Reuse owner-gated F0-138: choose DoH or DoT, fixed trusted
resolver configuration, certificate/redirect rules, and a three-state DNSSEC assurance contract.
Do not require DNSSEC for all tenants without a separate compatibility decision, and do not call AD
bit reporting end-to-end application validation.

### F5 — Plaintext token output has no end-to-end leak sentinel

**Classification:** implemented hash-only storage with a confirmed validation gap; future API/UI
flow. **Severity:** medium.

**Evidence.** `issue` and `reissue` return the plaintext challenge to their caller
([issue/reissue](../../apps/custom-domain-verification/verification.js#L32-L55),
[reveal](../../apps/custom-domain-verification/verification.js#L180-L188)); storage receives only
the bound hash ([create call](../../apps/custom-domain-verification/verification.js#L32-L40)). There
is no custom-domain API, UI, audit event, or sentinel test proving that the value stays out of
request logs, response logs, audit payloads, telemetry attributes, error responses, and later UI
state. F0-117 requires token-free durable audit but does not by itself inspect every output sink.

**Abuse preconditions.** Future API/UI code logs or persists the add/reissue result, an error embeds
it, or an operator/insider can read a sink that captures plaintext before DNS publication.

**Impact.** The TXT value is public after publication and is not a bearer proof for another
tenant/domain because of binding, so leakage does not bypass that control. It does expose
pre-publication material, increases operational data sensitivity, and could enable replay if later
code accidentally weakens binding.

**Suggested mitigation, not adopted.** Make add/reissue the only plaintext response, never include
the value in durable audit or telemetry, redact it from structured logs, and add one sentinel value
that is asserted absent across logs/audit/telemetry/errors and asserted present only in the intended
response. Recovery should rotate rather than retrieve stored plaintext.

### F6 — A future check-now endpoint needs a shared DNS-work budget

**Classification:** future flow with a confirmed acceptance gap. **Severity once reachable:** medium
to high for availability.

**Evidence.** One check starts with a CNAME lookup and then makes a TXT lookup only when the challenge
owner has no CNAME. The bounded eight-hop traversal can entail up to nine owner queries before it
returns or rejects ([challenge check](../../apps/custom-domain-verification/verification.js#L69-L103),
[CNAME traversal](../../apps/identity-provider/management/dns-lookup.js#L93-L140)). Per-query
resolver count, attempts, and timeout are bounded, but no global or registrable-domain concurrency
or rate budget exists. F0-117 specifies per-tenant and per-domain manual rate limits. Those can be
bypassed by multiple tenants and do not reserve capacity for scheduled re-verification. PR #257's
negative-cache metadata is useful for scheduler timing, but it is unmerged and does not throttle a
manual caller by itself.

**Abuse preconditions.** A compromised or hostile tenant can invoke future check-now calls, possibly
across many tenants/domains, and points challenge names at slow or targeted authoritative DNS.

**Impact.** Worker/socket exhaustion, delayed legitimate verification and re-verification, or
amplified query load against a victim authoritative server. The response returns to the caller, so
this is query amplification/resource exhaustion rather than a reflected response flood.

**Suggested mitigation, not adopted.** Keep F0-117's tenant/domain limits and add a shared
cross-worker concurrency/rate budget, fairness by registrable domain, bounded queueing, and reserved
capacity for active-domain safety checks. The owner must confirm limits, storage/enforcement
boundary, and overload behavior before implementation.

### F7 — Arbitrary branded-login phishing has no operating control

**Classification:** future flow and confirmed policy/ownership gap. **Severity once arbitrary custom
hosts serve login:** high.

**Evidence.** No custom-domain host currently routes. F0-119 plans routing only for `active` domains;
that proves platform eligibility, not honest intent. DNS ownership, normalized labels, and valid TLS
do not establish brand authorization. There is no abuse-report channel, operator host block,
restoration procedure, durable reason/actor audit, or business-verification policy in current source
or the reviewed downstream issue acceptance.

**Abuse preconditions.** A tenant legitimately controls a misleading host and future routing serves
the identity-provider login surface there.

**Impact.** Scalable credential phishing under a valid certificate, harm to impersonated brands,
and emergency-response pressure without a safe stop/restore mechanism.

**Suggested mitigation, not adopted.** The owner must choose a posture: reactive abuse response;
protected-brand screening; manual pre-activation review; or tenant business verification. At
minimum, propose an operator-only serving inhibit that tenant actions cannot clear, durable
actor/reason audit, an appeal/restoration procedure requiring fresh proof, and a named operational
role. None of those choices is approved by this review.

## Proposed follow-up issue text for coordinator triage

These are drafts, not created issues or assignments. “Owner role” describes the accountable
function the coordinator should staff after the human owner confirms the relevant decision.

### 1. Bound stale-domain serving and fence ownership handoffs

**Proposed scope.** Extend F0-116/F0-119/F0-120 or create one coordinated security follow-up that
defines proof freshness, continuous transient-failure handling, removal/loss serving inhibition,
restoration preconditions, and ownership generations across application cache, scheduler,
controller, route, and certificate work.

**Proposed acceptance.** A human-approved loss-to-denial objective is enforced independently on the
request path; stale jobs from an old generation cannot restore or delete a new owner's resources;
loss/removal suppresses new reconciliation; restoration requires fresh proof and current routing/TLS
readiness; outage behavior is explicit and tested.

**Proposed owner roles.** Custom-domain lifecycle, persistence, and ingress/controller owners, with
security review. **Decision needed:** takeover window and fail-open/fail-closed outage policy.

### 2. Resolve pending custom-domain claim squatting

**Proposed scope.** Decide whether an unverified add reserves a host or the first successful proof
wins, then specify pending expiry, retry/re-add behavior, conflict privacy, anti-churn controls, and
atomic handoff.

**Proposed acceptance.** Expired pending rows cannot block a legitimate claimant indefinitely;
concurrent proof has one deterministic winner; responses do not enumerate another tenant's claim;
tenant limit and fresh-proof requirements remain enforced; stale work is generation-fenced.

**Proposed owner roles.** Persistence and custom-domain lifecycle owners. **Decision needed:** retain
or replace the approved non-removed-host uniqueness policy.

### 3. Prove verification tokens stay out of observability and retained UI state

**Proposed scope.** Add to F0-117/F0-118 the explicit output contract and sentinel validation for
add/reissue tokens across logs, durable audit, telemetry, errors, and UI persistence.

**Proposed acceptance.** A unique sentinel appears only in the intended add/reissue response and is
absent from every captured sink; storage remains hash-only; recovery rotates the challenge; audit
records actor, domain identifier, action, and outcome without token plaintext or raw DNS answers.

**Proposed owner roles.** Management API, UI, observability, and security-test owners. No new token
derivation or recovery policy is selected here.

### 4. Enforce a global DNS verification work budget

**Proposed scope.** Complement F0-117's tenant/domain rate limits and F0-116 scheduling with a shared
cross-worker lookup budget, registrable-domain fairness, bounded queue, and reserved safety-check
capacity.

**Proposed acceptance.** Many tenants cannot exceed the global or target-domain budget; manual work
cannot starve active-domain re-verification; overload fails with a sanitized retry response; DNS
attempt, CNAME, timeout, and negative-cache bounds remain effective.

**Proposed owner roles.** Runtime-capacity, management API, and scheduler owners. **Decision needed:**
shared enforcement boundary, numeric limits, fairness, and overload behavior.

### 5. Complete encrypted resolver transport and DNSSEC assurance

**Proposed scope.** Reuse [F0-138](https://linear.app/fid/issue/F0-138/add-encrypted-dns-transport-and-dnssec-status),
after its prerequisite lands; do not create a duplicate.

**Proposed acceptance.** Use only owner-approved fixed resolver endpoints; deterministic timeout,
size, redirect, certificate, and failure behavior; report authenticated/not-authenticated/not-requested
without claiming more than the configured resolver established.

**Proposed owner roles.** DNS/resolver security and runtime-configuration owners. **Decision needed:**
DoH versus DoT, resolver trust and certificate policy, and the assurance contract.

### 6. Define branded-host and confusable-name abuse operations

**Proposed scope.** Choose and document launch posture for single-script/ASCII confusables and
ownership-valid phishing; add reporting, emergency serving inhibit, durable actor/reason audit,
appeal, and restoration procedures appropriate to that posture.

**Proposed acceptance.** The selected screening/review rule has a maintainer and exception process;
an authorized operator can stop serving without changing ownership; tenant actions cannot clear an
operator block; restoration requires policy clearance and fresh technical proof; response targets
are documented and exercised.

**Proposed owner roles.** Security/abuse operations, product policy, custom-domain routing, and UI
owners. **Decision needed:** reactive handling, brand screening, manual review, or business
verification; who staffs response and appeals.

## Decisions that must remain human-owned

1. Maximum proof age and loss-to-denial objective, including DNS/controller outage behavior.
2. Reservation-on-add versus first-valid-proof claim semantics and migration/handoff policy.
3. DoH versus DoT, resolver trust/certificate policy, and DNSSEC assurance contract in F0-138.
4. Global DNS budget location, limits, fairness, overload behavior, and reserved safety capacity.
5. Brand/confusable admission policy, abuse-response posture, operator authority, and appeal owner.
6. Whether future routing eligibility also requires the host's routing records to point at approved
   platform targets; TXT ownership proof alone does not answer that question.

Until those decisions are confirmed and future flows have executable acceptance evidence, F0-122
should remain an evidence package for coordinator triage, not a claim that custom domains have
completed general-availability security review.
