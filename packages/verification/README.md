# Custom-domain verification

This private JavaScript workspace library owns the custom-domain DNS challenge lifecycle and its
repository port. The consuming application injects the repository, DNS lookup, clock, and random
byte source. The library creates no database or network connections and has no Fastify, OIDC, or
identity-provider dependency.

The identity provider keeps the concrete PostgreSQL repository, schema, migration, DNS resolver,
and application composition. Its adapter enforces the final expiry, state, and challenge hash
guards atomically against database time.
