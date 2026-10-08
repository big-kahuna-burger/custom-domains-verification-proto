import { build, preview } from 'vite'

const requestedPort = Number(process.env.PORT ?? 5173)
if (!Number.isSafeInteger(requestedPort) || requestedPort < 1 || requestedPort > 65_535) {
  throw new TypeError('PORT must be an integer between 1 and 65535')
}

const watcher = await build({ mode: 'development', build: { watch: {} } })
if (!('on' in watcher)) throw new TypeError('Bundled development build did not start a watcher')

await new Promise((resolve, reject) => {
  watcher.on('event', (event) => {
    if (event.code === 'END') resolve()
    if (event.code === 'ERROR') reject(event.error)
  })
})

const server = await preview({
  mode: 'development',
  preview: {
    host: '0.0.0.0',
    port: requestedPort,
    strictPort: true,
    headers: { 'x-amp-review-widget': 'off' }
  }
})
server.printUrls()

let closing = false
async function close() {
  if (closing) return
  closing = true
  await Promise.all([server.close(), watcher.close()])
}

process.once('SIGINT', close)
process.once('SIGTERM', close)
