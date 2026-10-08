# Identity-provider integration (reference)

This directory holds the custom-domain code that ran inside the f0 identity provider, moved here
as-is when custom domains were taken out of that repository. It is reference material: it imports
the identity provider's Fastify app, PostgreSQL helpers and test harness, which are not part of this
repository, so it does not run on its own.

| Path                                    | What it was                                                       |
| --------------------------------------- | ----------------------------------------------------------------- |
| `management/custom-domains.js`          | Composition of the lifecycle with the repository and DNS lookup   |
| `management/custom-domain-name.js`      | UTS #46 host canonicalization and rejection rules                 |
| `management/dns-lookup.js`              | Bounded TXT lookup, CNAME traversal, in-memory test lookup        |
| `management/node-dns-lookup.js`         | Resolver-backed lookup over configured IP addresses               |
| `management/dns-wire-query.js`          | UDP/TCP wire query used by the resolver-backed lookup             |
| `management/routes/v1/custom-domains/`  | `/manage/v1/custom-domains` Fastify routes                        |
| `persistence/custom-domain-repository.js` | Drizzle/PostgreSQL implementation of the repository port        |
| `fragments/`                            | Pieces cut out of shared IdP files: SQL, Drizzle table, DTOs, env config, OpenAPI, composition |
| `test/`                                 | Unit and PostgreSQL integration tests for the above               |

Third-party dependencies used here: `dns-packet`, `drizzle-orm`, `fastify`, `tldts`, `tr46`,
`unicode-properties`, `zod`.

## Management API (as served by the identity provider)

This identity provider's custom domains are managed through `/manage/v1/custom-domains` (see the
OpenAPI document at `/reference/`). Adding a domain returns the ownership TXT record to publish at
`_f0-challenge.<host>`. Its value is returned only by add and reissue. Only a hash is stored, and it
never appears in reads, logs or audit events. `POST /custom-domains/{id}/verification-checks` checks the
record on demand. Each domain gets one check per minute and the provider gets ten in total. One
process holds at most ten domains that are not removed.

| Environment variable        | Meaning                                                                                |
| --------------------------- | -------------------------------------------------------------------------------------- |
| `CUSTOM_DOMAIN_DNS_SERVERS` | Up to four comma-separated resolver IP addresses for checks. Unset: checks answer 503. |

Every management request is authorized by the verified token's scopes alone. The domains belong to
this identity provider, so there is no stored ownership record to consult and no tenant claim is
read from the token or the request. A token without the operation's scope answers 403, and a
missing or removed domain answers 404.

Administration is scoped to the process: a deployment that must keep two sets of domains apart runs
two identity providers with separate databases.

### Manual end-to-end check

Run this from a local or staging deployment, never from CI, with a domain you control. The
example uses `attest.me`:

1. Set `CUSTOM_DOMAIN_DNS_SERVERS`.
2. With a token holding `write:custom_domains`, `POST /manage/v1/custom-domains` with
   `{ "host": "login.attest.me" }`. Keep the returned `challenge`.
3. Publish a TXT record named `challenge.recordName` with the value `challenge.recordValue` at your DNS
   provider.
4. With `update:custom_domains`, `POST /manage/v1/custom-domains/{id}/verification-checks` until it
   returns `"verified": true`. Wait a minute between checks.
5. With `delete:custom_domains`, `DELETE /manage/v1/custom-domains/{id}`, then remove the TXT record.

