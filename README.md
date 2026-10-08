# Custom domains verification (prototype)

DNS ownership verification for custom domains: a host is added, a `_f0-challenge.<host>` TXT
record is issued, and an on-demand check verifies it. Extracted from the f0 identity provider.

| Path                    | Contents                                                                    |
| ----------------------- | --------------------------------------------------------------------------- |
| `packages/verification` | Challenge lifecycle library with injected repository, DNS, clock and random |
| `packages/contract`     | Management API operations, scopes, JSON schemas and error codes             |
| `demo`                  | React demo of the add / verify / reissue / remove flow over the contract    |
| `idp-integration`       | Reference copy of the identity-provider routes, persistence and DNS adapter |
| `docs`                  | Threat model and abuse review                                               |

```sh
pnpm install
pnpm test
pnpm --filter @custom-domains/demo dev
```

The docs link to files by their former paths in the identity-provider repository; the same files
live under `idp-integration/` and `packages/verification/` here.
