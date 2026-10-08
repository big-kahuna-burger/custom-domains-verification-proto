// Runtime config entry, as it sat in the IdP's config/runtime.js (zod env schema).

  // Recursive resolvers for custom-domain ownership checks. Without them checks answer 503.
  CUSTOM_DOMAIN_DNS_SERVERS: z.preprocess(
    blankAsUndefined,
    z
      .string()
      .transform((value) => value.split(',').map((server) => server.trim()))
      .pipe(
        z
          .array(
            z.string().refine((server) => isIP(server) !== 0, {
              error: 'CUSTOM_DOMAIN_DNS_SERVERS must be a comma-separated list of IP addresses'
            })
          )
          .min(1)
          .max(4, 'CUSTOM_DOMAIN_DNS_SERVERS accepts at most 4 resolvers')
      )
      .optional()
  )

// mapped as: customDomainDnsServers: config.CUSTOM_DOMAIN_DNS_SERVERS
