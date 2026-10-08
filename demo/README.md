# Custom domains browser demo

A standalone React demonstration of the shipped custom-domain management contract. It is a design
and interaction aid, not a management console, deployable, or Watt application. An in-memory
transport keeps the journey deterministic while `src/api.js` builds every request from
`@f0/management-contract` operation metadata and consumes the current response shapes.

```sh
pnpm --filter @f0/demo-custom-domains dev
pnpm --filter @f0/demo-custom-domains test
pnpm --filter @f0/demo-custom-domains build
```

The development command watches a bundled Vite build and serves it through Vite preview. Reload
after an edit to pick up the rebuilt bundle; this avoids source-module and portal review-widget
waterfalls. Production builds are unaffected.

Use **Demo state** to inspect setup, recovery, all five public statuses, empty, loading, request
failure, and the ten-domain limit. Add/reissue responses expose the TXT value once in local React
state. List responses intentionally cannot recover it. Ownership verification is the demo's stop
point; serving readiness is not represented by the current contract.
