# Threat model: domain takeover and custom domain abuse

Status: review draft for the Custom Domain Manager project (Threat model domain takeover and custom
domain abuse). End-to-end custom-domain serving is not complete; normalization and persistence
have landed on the experimental integration branch. This model reviews the design before general
availability. It records findings and options. It does not record any architectural
decision. Every item marked **awaiting owner confirmation** changes architecture, ownership, trust
boundaries, runtime topology, public contracts, persistence boundaries or security policy, and
under `AGENTS.md` it needs explicit confirmation from the human owner before anyone implements it.
Confirmed owner decisions that this model builds on are cited by issue title and in the decision matrix.

Later change: in-process tenancy has since been retired, so the single identity provider has no
tenant, membership or tenant-ownership record. Where this model says a domain, challenge, key set,
quota or route belongs to a tenant, read it as belonging to one identity provider process; keeping
two sets of domains apart means running two processes with separate databases. The cross-tenant
races, tenant-selector and per-tenant-budget findings still apply between processes, and the
management-API findings that rest on tenant membership no longer have an in-process control to
rest on.

Sources: the issues Store tenant custom domains with a limit of 10, Normalize and validate custom
domain names, Add a DNS lookup port for domain verification, Issue and check DNS verification
challenges, Schedule verification retries and periodic re-verification, Manage custom domains
through the management API, Show custom domains and DNS instructions in the management UI, Route
requests on custom domains to their tenant, Provision certificates for verified custom domains,
Serve OIDC correctly on custom domains, Publish a read-only verified-host list for the ingress
controller, and Build the controller that syncs verified hosts to the ingress. Confirmed decisions:
Decide the domain verification record format, Decide how custom domains relate to the issuer (one
issuer per custom domain), Decide who issues and terminates TLS for custom domains (ingress owns
TLS, separate controller), and Decide signing keys and client scope for per-domain issuers (one
signing key set per tenant, a client works on every active domain of its tenant).

Issue keys in the mitigation map and decision matrix identify downstream implementation work.

## Scope

In scope: the life cycle of a tenant-owned host (add, verify, route, certify, serve OIDC, lose,
remove), the management API and UI that drive it, the DNS lookup adapter, the verified-host list and
ingress controller, and per-request host resolution.

Out of scope: general TLS configuration of the ingress, the default platform domain, and tenant
account security not specific to domains.

## Assets

| Asset                                             | Why it matters                                                                         |
| ------------------------------------------------- | -------------------------------------------------------------------------------------- |
| The mapping host to tenant (custom domain record) | Decides which tenant, issuer, cookies, keys and clients answer on a host.              |
| The verification token                            | Proves control of a DNS name. Its integrity is binding to tenant and domain.           |
| Tenant signing key set                            | Signs every token for the tenant on every host (owner decision on per-domain issuers). |
| Sessions, authorization codes, refresh tokens     | Bound to the issuing issuer. Cross-host use would be account takeover.                 |
| WebAuthn credentials                              | The RP ID is the custom domain. Loss of the domain strands them.                       |
| Certificates and their ACME accounts              | A certificate for a host the tenant no longer controls is a takeover primitive.        |
| Verified-host list and controller cluster access  | The controller is the only component with cluster write access for custom domains.     |
| Identity provider DNS and outbound egress         | Verification makes the service issue DNS queries on behalf of tenants.                 |
| Platform brand and users' trust in login pages    | Arbitrary branded login hosts can be used for phishing.                                |

## Trust boundaries

1. Internet to ingress: the ingress terminates TLS and forwards to the identity provider. Only the
   ingress may supply forwarding headers.
2. Ingress to identity provider: the effective host is the only tenant selector on this path.
3. Tenant administrator to management API: authenticated by management scope and tenant membership.
4. Identity provider to recursive resolver to public DNS: the answer is influenced by whoever
   controls the zone, and by on-path attackers if the resolver path is not protected.
5. Identity provider to controller (verified-host list): a read-only workload client, still to be
   confirmed by the owner.
6. Controller to cluster API and to the ACME certificate authority: the controller holds the only
   write access, and the CA validates control of the name independently of the identity provider.

## Attackers

| Attacker                              | Capability                                                               |
| ------------------------------------- | ------------------------------------------------------------------------ |
| Hostile tenant                        | Valid management access to one tenant, can add up to 10 domains, races.  |
| Domain squatter or former owner       | Controls DNS for a name that a tenant previously verified or lapsed.     |
| Third party with dangling DNS access  | Can register an unclaimed target that a tenant's CNAME still points at.  |
| External phisher                      | Registers look-alike names and asks the service to host a login page.    |
| Network attacker                      | On-path or off-path DNS spoofing toward the resolver.                    |
| Malicious client                      | Sends arbitrary Host and forwarding headers, replays codes across hosts. |
| Insider with log or audit read access | Can read logs, audit events and the UI.                                  |
| Compromised tenant tooling            | Has a valid management token and automates "check now".                  |

## Abuse cases and mitigations

Mitigations cite the planned issues by title. "Gap" means the planned issue does not fully cover the
case; the follow-up is listed under Findings to file and Options awaiting owner confirmation.

### 1. Dangling DNS and subdomain takeover

A tenant removes a domain, or lets its zone or CNAME target lapse. Someone else can then make the
name resolve to infrastructure they control while the platform still routes or holds a certificate
for it. A lapsed domain re-registered by a squatter can also pass an old verification if the
platform has not yet re-checked.

- Periodic re-verification with a grace period and a `verification_lost` state (Schedule
  verification retries and periodic re-verification). Only definitive negatives (NXDOMAIN, NODATA)
  count, so a resolver outage cannot drop a tenant.
- Gap: a lapsed registration or deleted zone often produces SERVFAIL (lame delegation) or a
  timeout, and a re-registered zone can answer NOERROR with a TXT set that lacks the token. The
  planned rule does not count SERVFAIL or timeout, so such a domain could stay `active` without a
  bound. The follow-up is a maximum age of continuous non-success, after which the domain is
  treated as lost, and an explicit rule that a TXT set present without the token is a definitive
  negative. See option A.
- Routing only for `active` domains, and withdrawal of route and certificate on loss or removal
  (Route requests on custom domains to their tenant; Provision certificates for verified custom
  domains; Build the controller that syncs verified hosts to the ingress).
- Gap: the re-check interval plus grace period is the takeover window. During it the platform
  serves a login page on a name the tenant may no longer control. See option A.
- Gap: verification proves control of the TXT label, not that the routing record still points at
  the platform. A tenant can keep the TXT record and repoint the A or CNAME elsewhere, and the
  platform can then hold a valid certificate for a host that resolves to someone else. See option B.

### 2. Verification token replay and leakage

An attacker who learns a token, or reuses one issued for another tenant or domain, verifies a
domain they do not own. Tokens can leak through logs, audit events, error messages, the UI, or
telemetry.

- CSPRNG token of at least 128 bits, bound to (tenant, domain), stored as a hash, expiry and
  rotation on re-issue, and a fresh challenge when another tenant re-adds a removed domain (Issue
  and check DNS verification challenges; Decide the domain verification record format).
- Audit events carry no token plaintext (Manage custom domains through the management API).
- A TXT token is public once published in DNS, so leakage from DNS is not a secret loss. An
  attacker who reads the plaintext before the owner publishes it can publish it only in a zone they
  control, so it is harmless as long as the token is bound to the tenant and domain. Binding is
  the load-bearing control, not secrecy. Log and audit hygiene is defense in depth and keeps the
  pre-publication window small, and hash-only storage limits what a database read reveals.
- Gap: "shown once or re-derivable only by the owner" leaves the storage mechanism open. A
  re-derivable token needs a server-side keyed derivation, which is a persistence and key
  management choice. See option C.
- Required tests: log, audit and telemetry sentinel checks that no verification value appears; the
  UI shows the token only in the add and re-issue responses.

### 3. TOCTOU between verification and certificate issuance

Verification succeeds at time T1. The domain lapses or changes owner before the controller requests
a certificate at T2 or before the CA validates at T3, or the domain is removed while a Certificate
resource is being reconciled.

- A certificate exists only for `verified` or `active` domains and is withdrawn on loss or removal;
  a domain goes `active` only after the ingress serves TLS with a matching certificate name
  (Provision certificates for verified custom domains).
- The CA performs its own domain control validation, independent of platform state. It proves only
  that the name resolves to the platform's ingress, not which tenant owns the host. A lapsed domain
  whose A or CNAME record still points at the ingress therefore still validates, so the CA is a
  backstop against names that no longer point at the platform and not a control against a stale
  tenant assignment. This is why option B matters.
- Gap: the controller acts on a polled list with an ETag, so state can be stale by the poll
  interval. Loss and removal must take effect on the next poll, and the controller must process
  deletions before creations. The controller keeps existing resources when the identity provider
  is unreachable, which is right for availability but means a takeover during an outage is not
  withdrawn. See option D.
- Residual: already-issued certificates stay valid until expiry after the Certificate resource is
  deleted. CAA pinning (option E) narrows who can issue but does not revoke.

### 4. Cross-tenant claim races

Two tenants add the same host concurrently, one adds a host while another removes it, or the limit
of 10 is raced with parallel inserts.

- Uniqueness across all tenants among non-removed rows and the limit of 10 enforced in
  PostgreSQL, tested under concurrency (Store tenant custom domains with a limit of 10).
- A foreign domain answers 404, not 403, so existence is not disclosed (Manage custom domains
  through the management API).
- Gap: because uniqueness covers every non-removed row, including `pending`, an unverified pending
  claim blocks the real owner until it expires or is removed. A squatter can therefore deny a name
  to the real owner by adding it first. Relaxing this means scoping uniqueness to verified rows (a
  partial unique index), so that the first tenant to prove control wins. That is a persistence
  change. See option F.
- Parent and child names (`example.com` and `login.example.com`) are independent claims. The
  exact-match challenge at each label is the right default, and each tenant must prove control of
  its own label.

### 5. Homograph and IDN spoofing

A tenant registers a name that uses a Cyrillic letter in place of a Latin one, or a mixed-script
name, to host a convincing login page under a trusted-looking host.

- UTS #46 and IDNA2008 normalization, A-label storage, U-label display, rejection of mixed-script
  confusables, and public-suffix and special-use rejection (Normalize and validate custom domain
  names). The UI shows the U-label next to the A-label (Show custom domains and DNS instructions in
  the management UI).
- Gap: mixed-script rejection does not stop single-script confusables (for example an all-Cyrillic
  look-alike of a Latin brand) or ASCII look-alikes (`rn` for `m`, digit `1` for `l`). Nothing in
  the plan compares against brand names. See option G.
- Residual: ASCII typosquats cannot be fully prevented without a deny-list or review.

### 6. Wildcard and apex handling

- Wildcards are rejected in v1 (Normalize and validate custom domain names). A wildcard claim would
  let one verification cover unbounded hosts, so this is the safe default. Revisiting it is a
  policy change and needs owner confirmation.
- An apex cannot carry a CNAME, so tenants use A or ALIAS records. The platform must not require a
  CNAME at the apex. HSTS is sent without `includeSubDomains` (Provision certificates for verified
  custom domains), so an apex login host does not force TLS on unrelated subdomains.
- Cookies are host-only (Serve OIDC correctly on custom domains). This matters most on an apex or
  parent domain, where a cookie scoped to the parent would be sent to every sibling. The model
  requires that no cookie sets a `Domain` attribute, with a test that asserts it.
- Public suffixes and the platform's own host and subdomains are rejected, which prevents claiming
  a registry suffix or shadowing the canonical issuer.

### 7. Certificate issuance abuse

- The controller creates Certificate resources only for listed hosts, one per host, so a verified
  domain cannot obtain a certificate for other names.
- Issuance volume: 10 domains per tenant bounds one tenant, but many tenants can drive ACME rate
  limits (orders and failed validations). Churn (add, verify, remove) can burn the platform's ACME
  quota. See option H.
- Certificate transparency makes every issued hostname public. The UI should tell tenants that
  adding a domain publishes it. Not a vulnerability, but a disclosure.
- The CAA pre-check is advisory. The CA performs the authoritative check.

### 8. Host header trust and cache poisoning

- The effective host comes from `Host`, or from `Forwarded` / `X-Forwarded-Host` only when trusted.
  Untrusted or conflicting values cannot select a tenant, and unknown hosts get a fixed error page
  that never falls through to the default tenant (Route requests on custom domains to their
  tenant).
- Current behaviour to change: `apps/identity-provider/application.js` today pins `Host` and
  `X-Forwarded-Proto` to the canonical issuer and deletes `X-Forwarded-Host` for every request, and
  `security/config.js` exposes `TRUST_PROXY` as a boolean. Host-based tenant resolution must
  replace that pinning with a resolved-host step, and that is the central trust-boundary change for
  custom domains. It needs owner confirmation as part of option I.
- Gap: trust of forwarding headers depends on the ingress being the only path. If the identity
  provider is reachable directly (a mis-scoped network policy or a node port), any client can set
  `X-Forwarded-Host`. The deployment must restrict the listener to the ingress and the code must
  trust forwarded headers only behind a configured proxy setting. See option I.
- Absolute URLs (discovery `issuer`, endpoints, redirect targets, email links) must be built from
  the resolved active domain, never from the raw header, or a confused host produces poisoned
  reset or verification links.
- Cache poisoning: any shared cache in front of the service must key on the host and must not
  cache responses that vary by forwarded headers. A discovery or JWKS document cached for host A
  and served on host B breaks `iss` matching (OIDC Discovery section 4.3). Host-dependent
  responses need `Vary: Host` semantics or no shared caching. The in-process host lookup cache is
  invalidated on state change; a stale positive entry is a takeover window equal to its TTL, so
  the TTL must be short and bounded.
- Cross-host code replay and mix-up: codes, refresh tokens and sessions are bound to the issuing
  issuer, `iss` is always returned in authorization responses, and cookies are host-only (Serve
  OIDC correctly on custom domains). Because one signing key set signs all of a tenant's hosts, a
  token signature is valid on every host of that tenant, so separation rests on `iss`, `aud` and
  issuer binding. A missing issuer check in any code path is a cross-domain token confusion inside
  one tenant. Tests must cover redemption at the wrong host.

### 9. DNS rebinding and resolver poisoning

- Lookups run only from the server side against a configured recursive resolver, with bounded
  timeouts and CNAME chain length, and the resolver target is never user input (Add a DNS lookup
  port for domain verification). This blocks using the verifier for server-side request forgery.
- Off-path spoofing of the TXT answer would let an attacker verify a domain they do not own. The
  plan supports DoT or DoH to the resolver and reports the AD bit when configured, both optional.
- DNS rebinding proper matters only if the platform fetches from the tenant's host. Verification is
  DNS-TXT only and the http-01 style fallback is off by default. If the fallback is ever enabled it
  must resolve once, check that the address is public, and connect to that same validated address
  (or re-validate at connect time), and must not follow redirects to private ranges. Checking by
  name and then connecting by name is the classic rebinding hole. The fallback comes from the
  recommendation in Decide the domain verification record format.
- Residual: without DNSSEC validation, verification trusts the resolver path. See option J.

### 10. "Check now" as a DNS amplifier

- Manual checks are rate limited per tenant and per domain, and background retries use backoff with
  a cap and respect negative TTLs (Manage custom domains through the management API; Schedule
  verification retries and periodic re-verification).
- One small authenticated request causes one or more outbound DNS queries, and a CNAME chain
  multiplies that. The chain is bounded. A tenant can point the label at a slow or hostile
  authoritative server to hold worker capacity, so timeouts and a global concurrency cap on lookups
  are needed. A per-tenant limit is bypassed by creating many tenants, so a global budget is the
  backstop. See option H.
- The response goes to the tenant (last failure reason), so the platform is not a reflector to third
  parties, but a victim's authoritative server can be queried at volume. A per-registered-domain
  limit covers this.
- Failure reasons in the UI and API must not echo raw DNS answers, which can contain
  attacker-controlled text.

### 11. Phishing on arbitrary branded login hosts

A verified tenant can serve a login page at any domain it controls, including look-alikes of other
brands, and benefits from valid certificates. Ownership proof does not prove legitimacy. Existing
controls (verification, homograph checks, audit) do not evaluate intent. See options G and K.

### 12. Other cases reviewed

- Enumeration through error differences: 404 for foreign domains and a fixed error page for unknown
  hosts, so responses do not reveal that a host is pending in another tenant.
- Verified-host list abuse: it carries hosts, issuers and states only, never tokens, and needs a
  dedicated read-only workload credential that a tenant token cannot use. The authentication
  mechanism is a trust boundary awaiting owner confirmation, already flagged in Publish a read-only
  verified-host list for the ingress controller.
- Controller or list-source compromise: the controller can bind certificates to any host it can
  name, and the identity provider can equally ask for any name. The CA's own validation stops
  names the attacker does not control.
- Delegated verification through a CNAME on the challenge label: a CNAME to a provider-controlled
  name lets whoever controls the target publish the tenant's token. If that target is dangling or
  lapses, a third party can register it and satisfy or re-satisfy verification, which is a
  takeover vector. Delegation is already refused by the confirmed verification-format decision.
  Accepting it later would require a separate owner decision, including target restrictions and
  recurring validation; bounded routing-CNAME traversal does not authorize challenge delegation.
- Passkey stranding: losing a domain strands WebAuthn credentials registered on it. That is an
  availability and recovery risk, not a takeover risk, because credentials are bound to the RP ID
  and to keys an attacker does not hold. Documentation is tracked in Serve OIDC correctly on custom
  domains.

## Mitigation map

| Threat                              | Planned control (issue title, key)                                                                                                             | Coverage |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| Dangling DNS, subdomain takeover    | Schedule verification retries and periodic re-verification (F0-116); withdrawal in Provision certificates (F0-120) and the controller (F0-132) | Partial  |
| Token replay, leakage               | Issue and check DNS verification challenges (F0-115); Manage custom domains through the management API (F0-117)                                | Partial  |
| TOCTOU verification to issuance     | Provision certificates for verified custom domains (F0-120); controller sync (F0-131, F0-132); CA validation                                   | Partial  |
| Cross-tenant claim races            | Store tenant custom domains with a limit of 10 (F0-112); Manage custom domains through the management API (F0-117)                             | Partial  |
| Homograph and IDN spoofing          | Normalize and validate custom domain names (F0-113); management UI screen (F0-118)                                                             | Partial  |
| Wildcard and apex handling          | Normalize and validate custom domain names (F0-113); Serve OIDC correctly on custom domains (F0-121)                                           | Covered  |
| Certificate issuance abuse          | Provision certificates for verified custom domains (F0-120)                                                                                    | Partial  |
| Host header trust                   | Route requests on custom domains to their tenant (F0-119)                                                                                      | Partial  |
| Cache poisoning                     | Route requests on custom domains to their tenant (F0-119) covers the host lookup, not shared cache rules                                       | Gap      |
| Cross-host token and code confusion | Serve OIDC correctly on custom domains (F0-121); depends on wrong-host redemption tests in every code path                                     | Partial  |
| DNS rebinding, resolver poisoning   | Add a DNS lookup port for domain verification (F0-114)                                                                                         | Partial  |
| "Check now" DNS amplification       | Manage custom domains through the management API (F0-117) rate limits; retries backoff (F0-116); no global budget                              | Partial  |
| Phishing on branded login hosts     | None                                                                                                                                           | Gap      |

## Findings to file

The parent issue requires findings to be filed as issues with owners. Filing is not part of this
document change. Suggested findings, all currently unfiled:

1. Global budget and concurrency cap on outbound verification lookups (option H).
2. Sentinel coverage that token plaintext is absent from logs, audit, telemetry and error responses.
3. Cookie and absolute-URL rules: no `Domain` attribute on any cookie, and every emitted absolute
   URL built from the resolved domain, with tests.
4. Cache rules for host-dependent responses (discovery, JWKS, error page) and a bounded host lookup
   TTL.
5. Listener restriction so only the ingress can reach the identity provider, plus a trusted proxy
   setting (option I).
6. Controller staleness handling: deletions before creations, and a maximum list age (option D).
7. Tenant-visible disclosure that certificate transparency publishes each hostname.
8. Failure-reason sanitisation: no raw DNS record text in the UI or API.

## Options awaiting owner confirmation

The incremental changes below await owner confirmation; already-confirmed baseline controls stay
in force. In particular, E1 retains the accepted CAA pre-check, and F3 would reverse an approved
persistence rule. The STRIDE matrix qualifies these recommendations and maps their issue impact.
Confirmation must be recorded with its source before implementing any policy change.

### A. Shorten the takeover window after loss

- A0 (applies to every choice below): bound continuous SERVFAIL or timeout, so that a domain that
  never yields a definitive answer is eventually treated as lost.
- A1: keep daily re-verification plus grace period. Cheapest. Window equals interval plus grace.
- A2: shorter interval (for example hourly) and a short grace. More lookups, tighter window.
- A3: A2 plus an immediate stop-serving switch for a tenant or operator, with the domain kept
  verified for restoration.
- Recommendation: A2 with A3, bounded by option H. **Awaiting owner confirmation.**

### B. Require a routing record check before `active`

- B1: verify the TXT record only (current plan).
- B2: also require that the host resolves to the platform's published target before `active`, and
  treat divergence as `verification_lost`.
- B3: B2 plus a platform-owned per-tenant CNAME target, so the platform can detect dangling targets
  it owns.
- Tradeoff: B2 and B3 add tenant setup steps and a second failure mode, in return for not serving
  hosts the tenant no longer points at the platform.
- Recommendation: B2. **Awaiting owner confirmation.**

### C. Verification token storage and recovery

- C1: show plaintext once, store only the hash, re-issue if lost. Simplest, no server-side secret.
- C2: derive the token with a server-side keyed function from (tenant, domain, epoch) so the owner
  can view it again. Adds a key to manage and rotate.
- Recommendation: C1. **Awaiting owner confirmation.**

### D. Controller staleness and outage policy

- D1: keep existing resources when the identity provider is unreachable (current plan).
- D2: D1 plus a maximum list age, after which the controller alerts.
- D3: after the maximum age the controller withdraws certificates. Safer against takeover, less
  available.
- Recommendation: D2. **Awaiting owner confirmation.**

### E. CAA pinning

- E1: advisory pre-check only (current plan).
- E2: tenants publish a CAA record naming the platform's CA and ACME account (RFC 8657
  `accounturi`), which restricts issuance for that name to the platform's account.
- Tradeoff: E2 imposes DNS changes on tenants and can reduce onboarding success.
- Recommendation: E1 for launch, E2 as an optional hardened mode. **Awaiting owner confirmation.**

### F. Reclaim and pending-claim policy

- F1: a name is free immediately on removal and needs a fresh challenge (current plan).
- F2: a removed or lost name is reserved for its previous tenant for a cooldown. Protects the
  former tenant but slows legitimate transfers and lets reservation be used for squatting.
- F3: F1 plus short expiry for pending claims, and uniqueness scoped to verified and active rows
  (a partial unique index) so the first tenant to prove control wins and unverified pending claims
  never block it.
- Recommendation: F3. It relaxes the planned uniqueness constraint in persistence. **Awaiting owner
  confirmation.**

### G. Brand and confusable policy

- G1: script and confusable checks only (current plan).
- G2: G1 plus a maintained deny-list of protected brand names with a skeleton comparison (UTS 39).
- G3: G2 plus manual review of flagged names before `active`.
- Tradeoff: G2 and G3 need a list owner and produce false positives. G3 needs a review process.
- Recommendation: G2 for launch, G3 when volume warrants. **Awaiting owner confirmation.**

### H. Global outbound and ACME budgets

- H1: per-tenant limits only (current plan).
- H2: H1 plus global concurrency and rate caps on lookups, per-registered-domain lookup limits, and
  an ACME order budget with churn limits per tenant.
- Recommendation: H2. **Awaiting owner confirmation.**

### I. Trusted proxy and listener exposure

- I1: keep today's boolean `TRUST_PROXY` and let deployment guarantee the ingress is the only
  path, with host resolution replacing the current issuer pinning.
- I2: I1 plus network policy, and a startup check that refuses to trust forwarded headers unless a
  trusted proxy address list is configured.
- Recommendation: I2. It changes runtime configuration and topology policy.
- Later change: the owner confirmed I2 for the forwarded-header half. `TRUSTED_PROXIES` replaced the
  boolean, an unset list trusts no hop, and the OIDC provider follows the same list instead of the
  issuer scheme. Network policy and listener exposure remain a deployment gate. The host-resolution
  half of this option lapsed with in-process tenancy.

### J. Resolver integrity

- J1: plain recursive resolver on a private network (current default).
- J2: J1 with DoT or DoH to a trusted resolver.
- J3: J2 plus DNSSEC validation with the AD bit reported as extra assurance. Requiring DNSSEC for
  all domains would exclude most tenants and is not recommended.
- Recommendation: J2 for launch and J3 as reported, not required, assurance. **Awaiting owner
  confirmation.**

### K. Phishing posture for branded login hosts

- K1: verified ownership is sufficient (current plan). Cheapest, and abuse is handled reactively.
- K2: K1 plus abuse reporting, a platform kill switch by host, and an audit trail.
- K3: K2 plus tenant business verification before the first custom domain. Raises onboarding
  friction and needs a verification process and owner.
- Recommendation: K2, with K3 evaluated before general availability. **Awaiting owner
  confirmation.**

## STRIDE owner decision matrix

This is a decision brief, not approval to implement. STRIDE: **S** spoofing,
**T** tampering, **R** repudiation, **I** information disclosure, **D** denial of service,
**E** elevation of privilege. Issue links identify exact downstream work; proposed additions
remain unapproved and unassigned.

### Confirmed baseline

- [Issuer model (F0-109)](https://linear.app/fid/issue/F0-109), [keys and clients
  (F0-123)](https://linear.app/fid/issue/F0-123), and the later [platform issuer decisions
  (F0-124)](https://linear.app/fid/issue/F0-124): one issuer per custom domain; one tenant key
  set and client scope across that tenant's issuers; platform issuers are per tenant at
  `https://<platform>/oidc/t/<tenant>`, with no global-issuer compatibility window.
  Wrong-issuer code, refresh-token and session rejection remains mandatory.
- [TLS decision (F0-110)](https://linear.app/fid/issue/F0-110): ingress-owned TLS and a
  separate controller; no certificates or Kubernetes credentials in the identity provider.
  CAA pre-check and reporting are already accepted. E1 must not weaken that requirement.
- [Verification format (F0-111)](https://linear.app/fid/issue/F0-111), owner comment
  dated 2026-09-30: exact-label TXT, at least 128 random bits, tenant/domain binding,
  seven-day expiry, **no CNAME delegation**, HTTP fallback off.
- [Normalization PR #218](https://github.com/big-kahuna-burger/f0tesla/pull/218) and
  [persistence PR #226](https://github.com/big-kahuna-burger/f0tesla/pull/226) are merged
  into `codex/experimental-custom-domains`, not evidence that the end-to-end feature is
  on main. PR #226 explicitly records owner approval of uniqueness across **all
  non-removed rows**. F3 therefore reverses an approved, implemented constraint.
- [DNS port PR #231](https://github.com/big-kahuna-burger/f0tesla/pull/231) remains a draft.
  Its owner-directed stack is F0-136 → F0-137 → F0-138. Reuse these issues; do not create
  duplicate DNS follow-ups or treat their public-contract gates as approved.

| Choice / STRIDE / cases | Recommendation and security benefit | Operational cost and alternatives | Exact downstream impact if approved |
| --- | --- | --- | --- |
| A — S/T/D; 1, 3 | **A0 + A2 + A3**: hourly checks, bounded non-success age and an immediate serving inhibit. Limits stale tenant ownership and supplies an emergency stop. | A1 is cheaper but leaves at least daily exposure plus grace. More DNS load and false suspensions during outages; see the two-hour target below. | [F0-116](https://linear.app/fid/issue/F0-116): add TXT mismatch as definitive failure, bounded SERVFAIL/timeout age and explicit timing. [F0-112](https://linear.app/fid/issue/F0-112): persist last successful proof and serving inhibit separately from ownership. [F0-117](https://linear.app/fid/issue/F0-117)/[118](https://linear.app/fid/issue/F0-118): stop/restore authorization, audit, UI. [F0-119](https://linear.app/fid/issue/F0-119)/[131](https://linear.app/fid/issue/F0-131)/[132](https://linear.app/fid/issue/F0-132): inhibit must override active/verified status, invalidate routing and suppress reconciliation. A verified-but-stopped host must not remain eligible simply because it is verified. |
| B — S/T; 1, 3 | **B2**, as a proposed routing-eligibility check, not ownership proof. Detects routing drift before activation and on re-check. | B1 remains simpler. B3 adds per-tenant target lifecycle. B2 adds DNS queries, propagation failures and multi-address/CDN complexity; support apex A/AAAA or ALIAS flattening, not mandatory CNAME. | [F0-114](https://linear.app/fid/issue/F0-114) and [136](https://linear.app/fid/issue/F0-136): new A/AAAA and bounded routing-chain contract, beyond today's TXT/direct-CNAME port. [F0-115](https://linear.app/fid/issue/F0-115)/[116](https://linear.app/fid/issue/F0-116): distinct routing evidence, platform-target matching and drift handling. [F0-120](https://linear.app/fid/issue/F0-120): activation gate; [F0-118](https://linear.app/fid/issue/F0-118): setup/failure guidance. Approve whether drift really means `verification_lost` or only serving-ineligible; do not silently equate routing with ownership. |
| C — S/I; 2 | **C1**: reveal once, hash only, rotate to recover. Preserves binding and reduces unnecessary plaintext exposure. | C2 adds a derivation secret and rotation/recovery complexity. C1 requires tenants to update DNS after losing the value. Public TXT values are not bearer secrets. | [F0-115](https://linear.app/fid/issue/F0-115): remove the re-derivation alternative; test expiry, rotation and tenant/domain binding. [F0-117](https://linear.app/fid/issue/F0-117)/[118](https://linear.app/fid/issue/F0-118): only add/re-issue reveals plaintext, explicit recovery UX. Keep [F0-112](https://linear.app/fid/issue/F0-112)'s hash-only storage. Add log/audit/telemetry sentinels and sanitized failure responses to these tests. |
| D — S/T/D; 1, 3, 12 | **D2** for launch availability, explicitly accepting that alerts do not withdraw stale resources. Stop new issuance from an over-age snapshot; process removals before additions. | D1 has no freshness alarm. D3 provides automatic outage withdrawal but can disable every tenant during a control-plane outage; deleting certificates alone is insufficient. | [F0-131](https://linear.app/fid/issue/F0-131): authenticated snapshot freshness/version contract (an authenticated 304 can confirm freshness). [F0-132](https://linear.app/fid/issue/F0-132): stale-age alert, no new issuance from stale data, deletion-first reconciliation and ownership-generation fencing. [F0-120](https://linear.app/fid/issue/F0-120): withdrawal verification. D3 would explicitly replace F0-132's keep-resources-on-outage acceptance and require route/serving withdrawal as well. |
| E — S/T; 3, 7 | **E1 at launch**, preserving the accepted CAA pre-check/reporting; optional **E2** only after CA support and the effective CAA policy are verified. | E2 adds tenant DNS work and account-rotation coupling. It constrains issuance, not existing certificates or a new DNS owner's ability to change CAA. | [F0-120](https://linear.app/fid/issue/F0-120): preserve pre-check and CA-authoritative validation. Optional E2 adds account-binding tests and renewal/rotation behavior; [F0-132](https://linear.app/fid/issue/F0-132): ingress-side account configuration; [F0-118](https://linear.app/fid/issue/F0-118): opt-in instructions. No ACME key moves into the identity provider. |
| F — S/T/D; 4 | **F3, conditional on explicit reversal of the PR #226 decision**: pending claims cannot squat a hostname; the first atomic successful proof wins. | F1 preserves the existing schema; F2 delays legitimate transfers and enables reservation abuse. F3 needs conflict handling, expiry cleanup and safe ownership handoff, not just a smaller unique index. | [F0-112](https://linear.app/fid/issue/F0-112): follow-up to #226 changing the index and transition transaction; retain 10 non-removed rows per tenant. [F0-115](https://linear.app/fid/issue/F0-115)/[116](https://linear.app/fid/issue/F0-116): atomic winner selection, fresh proof on reacquisition and pending expiry. [F0-117](https://linear.app/fid/issue/F0-117)/[118](https://linear.app/fid/issue/F0-118): non-enumerating conflict/expiry UX. [F0-119](https://linear.app/fid/issue/F0-119)/[131](https://linear.app/fid/issue/F0-131)/[132](https://linear.app/fid/issue/F0-132): fence old ownership generations so stale jobs cannot restore or delete a new owner's route. Lost/paused rows must not retain serving rights after releasing uniqueness. |
| G — S; 5, 11 | **G2 at launch only with a named list maintainer and exception process**. Adds protected-brand skeleton matching to existing normalization. | G1 misses single-script and ASCII look-alikes. G2 creates false positives and maintenance work; G3 adds staffed pre-activation review. None proves legitimacy. | [F0-113](https://linear.app/fid/issue/F0-113) is Done: use a separate policy follow-up to #218 rather than claim this is existing normalization acceptance. [F0-117](https://linear.app/fid/issue/F0-117)/[118](https://linear.app/fid/issue/F0-118): enforce/explain policy and exceptions. New brand-policy ownership work must be filed and assigned after approval. |
| H — D; 7, 10 | **H2**: global lookup concurrency/rate limits, registrable-domain fairness and ACME/churn budgets resist multi-tenant exhaustion. | H1 is bypassable across tenants. H2 needs shared enforcement across workers, capacity planning and queue fairness; reserve capacity for active-domain re-checks. | [F0-114](https://linear.app/fid/issue/F0-114)/[136](https://linear.app/fid/issue/F0-136): bounded per-operation work; [F0-116](https://linear.app/fid/issue/F0-116)/[117](https://linear.app/fid/issue/F0-117): shared budget across manual/background callers; [F0-137](https://linear.app/fid/issue/F0-137): negative-cache timing. [F0-120](https://linear.app/fid/issue/F0-120)/[132](https://linear.app/fid/issue/F0-132): ACME budget enforced where orders originate, including retries/renewals. A new cross-worker budget contract needs an owner and approved limits. |
| I — S/T/I/E; 8, 12 | **I2**: ingress-only network reachability plus trusted proxy addresses checked on actual connections. Stops attacker-controlled forwarded headers selecting tenants. | I1 relies wholly on deployment correctness. I2 requires proxy-address lifecycle and network-policy rollout; a startup list alone provides no runtime enforcement. | [F0-119](https://linear.app/fid/issue/F0-119): runtime peer/header validation, reject conflicting hosts, bounded cache and resolved-host URLs. [F0-121](https://linear.app/fid/issue/F0-121): host-only cookie, wrong-issuer and URL tests. [F0-132](https://linear.app/fid/issue/F0-132)'s Kubernetes deployment dependency: ingress-only listener policy and direct-access tests. New shared-cache/deployment acceptance must identify an Infra owner; its issue ID is not established here. |
| J — S/T; 9 | **J2 at launch + J3 as reported assurance**, not a DNSSEC-only admission rule. Protects the path to the configured resolver; does not prove tenant legitimacy. | J1 is cheaper but trusts the network path. DoH/DoT adds resolver operations and certificate policy. DNSSEC-bogus responses must not silently become successful unsigned verification. | [F0-138](https://linear.app/fid/issue/F0-138), not the reduced F0-114: choose DoH versus DoT, TLS/redirect policy, fixed trusted endpoints and three-way DNSSEC status; retain its owner gate and stack after [F0-137](https://linear.app/fid/issue/F0-137). [F0-115](https://linear.app/fid/issue/F0-115)/[116](https://linear.app/fid/issue/F0-116): consume typed failures and assurance. AD is a trusted resolver's assertion, not independent end-to-end validation by this app. |
| K — S/R/D; 11, 12 | **K2**: abuse reporting, operator host kill switch and durable actor/reason audit. Provides response after ownership-valid phishing. | K1 leaves response informal. K3 adds business-verification friction and staffing and is a separate future decision, not a launch prerequisite. | [F0-117](https://linear.app/fid/issue/F0-117): separately authorized operator action/audit; tenant APIs must not clear an operator block. [F0-118](https://linear.app/fid/issue/F0-118): status/reporting; [F0-119](https://linear.app/fid/issue/F0-119)/[131](https://linear.app/fid/issue/F0-131)/[132](https://linear.app/fid/issue/F0-132): same serving inhibit as A3. New abuse-operations issue needs a named responder and restoration procedure. |
| CNAME delegation — S/T/E; 9, 12 | **Refuse; already confirmed in F0-111.** TXT must be at the exact challenge label. Keep HTTP fallback off. | Tenants must manage the TXT directly. Supporting delegation would reopen an accepted trust boundary, not fill an unanswered question. Routing CNAMEs remain a different feature. | [F0-115](https://linear.app/fid/issue/F0-115): reject alias-derived challenge proof on initial and recurring checks. [F0-114](https://linear.app/fid/issue/F0-114)/[136](https://linear.app/fid/issue/F0-136): preserve enough alias provenance to reject it; a resolver-followed terminal TXT is insufficient evidence of an exact-label record. [F0-118](https://linear.app/fid/issue/F0-118): direct-TXT instructions. F0-136 traversal support must not silently authorize challenge delegation. |

### Recommended takeover-window value

**Propose two hours as the operational withdrawal target**, pending owner approval.
Use an hourly active-domain check, at most 30 minutes of retry/grace after the first
failed check, and at most five minutes each for scheduler/deadline slippage, application
cache invalidation and controller/ingress withdrawal: 60 + 30 + 5 + 5 + 5 = 105 minutes,
leaving 15 minutes of margin. These are proposed acceptance budgets, not measured guarantees.
H2 must reserve enough capacity to meet them; negative-cache delays must not extend serving grace.

A0 should separately prohibit serving with proof older than two hours since the last
successful fresh observation, even during continuous SERVFAIL/timeouts or worker starvation.
The request path must enforce this expiry independently of the worker that schedules checks.
Failed checks, manual retries, restoration requests and cached responses must not reset proof age.
A3/K2 should target effective request denial within five minutes of an accepted stop command,
with restoration requiring current proof, routing/TLS readiness and clearance of any operator block.

The target is measured from **loss becoming observable through the configured resolver**;
DNS TTLs, stale-answer policy, and a new owner retaining the old public TXT can hide actual
ownership loss. Periodic TXT checking cannot guarantee detection of a registration transfer
that preserves the records. F0-115/F0-116 must also reconcile the already-confirmed seven-day
token expiry with active-domain token rotation; this brief does not silently make tokens perpetual.

**D2 does not provide a hard two-hour end-to-end bound during controller/list outages.**
Propose a five-minute stale-list alert and no new issuance from stale snapshots, while retaining
resources as F0-132 currently requires. Application proof expiry can deny requests while the
application is reachable, but route/certificate withdrawal remains unbounded under D2.
If the owner requires a hard serving bound during control-plane outages, choose a D3-style
expiring serving lease enforced at the edge and explicitly change F0-132's outage policy.
Certificate deletion is neither cryptographic revocation nor sufficient proof that traffic stopped.

### Remaining acceptance and validation

No owner decisions, issue assignments or Linear acceptance criteria are changed by this matrix.
The eight findings above still need filed/assigned implementation work before F0-122 can be
completed. Use the mapped existing issues where they fit; create only the explicitly missing
policy/budget/abuse/deployment work after approval. The workload authentication gate in F0-131
also remains open; choosing I2 or D2 does not approve its credential mechanism.

After approval, focused acceptance should cover: virtual-clock loss/outage deadlines; concurrent
proof/reclaim/restore races in PostgreSQL; challenge alias rejection and token rotation; stale
controller snapshots and ownership-generation fencing; kill-switch persistence; direct-origin
host spoofing; wrong-issuer redemption; and DNS/ACME budget exhaustion. Treat host-dependent
shared-cache isolation as an explicit cache-key/configuration rule or disable shared caching;
a `Vary: Host` header alone is not a sufficient defense against forwarded-host confusion.

Standards context: [RFC 8657](https://www.rfc-editor.org/rfc/rfc8657.html) constrains the
CAA property carrying `accounturi`; an unconstrained alternative authorization can defeat the
intended pin. [RFC 4035 §4.9.3](https://www.rfc-editor.org/rfc/rfc4035.html#section-4.9.3)
requires trust in the resolver and its communication path before relying on AD.

## Residual risks

- Interval-based verification adds interval, grace, DNS visibility, scheduling, cache and controller
  delays. D2 does not bound withdrawal during controller outages; see the proposed timing budget.
- Issued certificates stay valid until expiry after the Certificate resource is deleted.
- Without DNSSEC on the tenant zone, verification trusts the resolver path.
- ASCII look-alikes and legitimately owned confusable names cannot be fully excluded.
- One signing key set per tenant makes cross-host separation depend on issuer and audience checks.
- Certificate transparency discloses every custom hostname.
- A takeover during an identity provider outage is not withdrawn under the current controller plan.
- Pending-claim squatting can deny a name to its real owner until the claim expires.
- ACME quota burn through add, verify and remove churn.
- Phishing on verified look-alike hosts is handled reactively unless option K is confirmed.
- A compromised controller or verified-host list source can request certificates for any name the
  attacker already controls in DNS and points at the ingress.

## Open questions for the owner

1. Which of options A to K are accepted, and who owns each resulting issue?
2. No CNAME-delegation decision is outstanding: retain the confirmed refusal unless separately reopened.
3. Are wildcard domains and an apex-only mode in scope after v1?
4. Is the proposed two-hour operational target accepted, and is D2 outage exposure acceptable or
   is a D3-style hard serving-expiry contract required?
5. Who runs abuse reporting and the platform kill switch?

## Review cadence

Revisit this model when any custom-domain issue changes scope, when the TLS or issuer decisions
change, and before general availability. Do not record run-specific results here.
