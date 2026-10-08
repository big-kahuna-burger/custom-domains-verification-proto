// Composition, as it sat in the IdP's application.js.
import { createCustomDomainManagement } from './management/custom-domains.js'
import { createCustomDomainRepository } from './persistence/custom-domain-repository.js'

const repositories = {
  customDomains: createCustomDomainRepository()
  // ...other repositories
}

// Custom-domain management: domains belong to this identity provider; DNS from configured
// resolvers only.
const customDomains = createCustomDomainManagement({
  repository: repositories.customDomains,
  identityProviderHost: parsedIssuer.hostname,
  dnsServers: runtimeConfig.customDomainDnsServers
})

// passed into the Fastify app as `customDomains`; the routes in
// management/routes/v1/custom-domains/ read it from the app options.
