import { StrictMode, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { createManagementClient } from './api.js'
import { CustomDomains } from './CustomDomains.jsx'
import { createDemoFetch, DEMO_SCENARIOS } from './demo-api.js'
import './styles.css'

function Demo() {
  const initialScenario = new URLSearchParams(window.location.search).get('scenario')
  const [scenario, setScenario] = useState(
    DEMO_SCENARIOS[initialScenario] ? initialScenario : 'setup'
  )
  const client = useMemo(
    () =>
      createManagementClient({
        issuer: 'https://id.f0.demo/oidc',
        token: 'demo-token',
        fetchImpl: createDemoFetch(scenario)
      }),
    [scenario]
  )

  return (
    <>
      <header className="demo-bar">
        <a className="wordmark" href="/" aria-label="F0 home">
          F0
        </a>
        <label>
          Demo state
          <select value={scenario} onChange={(event) => setScenario(event.target.value)}>
            {Object.entries(DEMO_SCENARIOS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
      </header>
      <CustomDomains key={scenario} client={client} />
    </>
  )
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <Demo />
  </StrictMode>
)
