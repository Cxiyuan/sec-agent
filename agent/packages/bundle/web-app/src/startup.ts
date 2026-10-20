/**
 * The web app's command-line provider: it parses the `dsh --profile web` flag
 * family (`--host`, `--port`, `--public-url`, `--trusted-host`, `--no-open`, TLS)
 * and its `--help` text, then provides the immutable values as
 * {@link WEB_STARTUP_SERVICE}. Ordinary rows inject that service before
 * reading it from lazy config.
 * @module @deepseek-ai/dsh-web-app/startup
 */

import { networkInterfaces } from 'node:os'
import { Command } from 'commander'
import type { Context } from '@deepseek-ai/cordis'
import { parseCmdline } from '@deepseek-ai/dsh-cmdline'
import { isWildcardHost, type TlsConfig } from '@deepseek-ai/dsh-host-webserver'
import { parsePublicUrl } from './public-url.ts'

/** Stable Cordis plugin name. */
export const name = 'web-startup'

/** Services required before the flags can be resolved. */
export const inject = ['cmdlineArgs']

/** Service provided by this ordinary plugin and injected by flag-configured rows. */
export const WEB_STARTUP_SERVICE = 'webStartup'

/** Environment variable naming a default bind address; an explicit `--host` outranks it. */
export const WEB_HOST_ENV = 'DSH_WEB_HOST'

/** Bind address of an invocation that names none and a machine that reports no LAN interface. */
const LOOPBACK_FALLBACK_HOST = '127.0.0.1'

/** Which layer named the effective bind address. */
export type BindHostSource = 'flag' | 'env' | 'lan' | 'loopback'

/** The `networkInterfaces()` facts the default resolution reads; the real table satisfies it. */
export interface BindHostInterfaces {
  readonly [name: string]: readonly {
    readonly family: string
    readonly address: string
    readonly internal: boolean
  }[] | undefined
}

/**
 * Resolve the bind address of an invocation that named no `--host`: the
 * {@link WEB_HOST_ENV} environment value when set and non-empty, otherwise
 * this machine's first non-internal IPv4 address — the LAN address browsers
 * on the same network dial — and loopback only when the machine reports
 * none. IPv4 only, the class LAN deployments use; an IPv6 literal stays an
 * explicit `--host` choice. The resolved address is one concrete interface
 * literal, never a wildcard, so the browser-trust fence keeps admitting
 * exactly this listener's own address beside loopback.
 * @param env - process environment to read.
 * @param interfaces - interface table to scan.
 * @returns the address and the layer that named it.
 */
export function resolveDefaultBindHost(
  env: Readonly<Record<string, string | undefined>>,
  interfaces: BindHostInterfaces,
): { host: string; source: BindHostSource } {
  const declared = env[WEB_HOST_ENV]
  if (declared !== undefined && declared !== '') return { host: declared, source: 'env' }
  for (const entries of Object.values(interfaces)) {
    for (const entry of entries ?? []) {
      if (entry.family === 'IPv4' && !entry.internal) return { host: entry.address, source: 'lan' }
    }
  }
  return { host: LOOPBACK_FALLBACK_HOST, source: 'loopback' }
}

/** What the web rows read from {@link WEB_STARTUP_SERVICE}. */
export interface WebStartupValues {
  /** Whether this invocation opens the default browser after startup. */
  openBrowser: boolean
  /**
   * Effective bind address, always present: `--host` when the invocation
   * named one, else {@link WEB_HOST_ENV}, else this machine's LAN address,
   * with loopback as the last resort.
   */
  host: string
  /** `--port`, absent when the invocation did not name one. */
  port?: number
  /**
   * `--public-url`, absent when not specified: the advertised HTTP(S) root.
   * See [public deployments](../README.md#public-deployments).
   */
  publicUrl?: string
  /** Explicit `--trusted-host` authorities, in argument order. */
  trustedHosts: string[]
  /** Server certificate chain and unencrypted private key supplied together. */
  tls?: TlsConfig
}

/** The web flag family, as commander parsed it. */
interface WebOptions {
  host?: string
  open: boolean
  port?: string
  publicUrl?: string
  trustedHost?: string[]
  tlsCert?: string
  tlsKey?: string
}

/**
 * This app's command: its flags, its description, and its help text.
 * @returns a fresh program, so one process can parse more than once (tests).
 */
function webCommand(): Command {
  return new Command()
    .name('dsh --profile web')
    .description('Serve the DeepSeek Harness browser UI.')
    .helpOption('-h, --help', 'show this help')
    .option('--host <host>', 'bind address: one concrete IPv4 or IPv6 literal of a local interface; wildcard addresses are rejected; defaults to this machine\'s LAN address')
    .option('--no-open', 'do not open the Web UI in the default browser')
    .option('--port <port>', 'listen port; pass 0 to let the OS pick a free one')
    .option('--public-url <url>', 'advertise this HTTP(S) root in the printed, opened, runtime-context, and DSH_WEB_URL forms; grants no trust')
    .option('--trusted-host <authority...>', 'extra authority the /api browser-trust fence accepts (host or host:port; repeatable)')
    .option('--tls-cert <file>', 'PEM server certificate chain; requires --tls-key')
    .option('--tls-key <file>', 'unencrypted PEM private key; requires --tls-cert')
    .addHelpText('after', `
Examples:
  dsh --profile web                          serve on this machine's LAN address (default)
  dsh --profile web --host 127.0.0.1         serve this machine only
  dsh --profile web --no-open                serve without opening a browser
  dsh --profile web --port 8080              serve on another port
  dsh --profile web --host 10.0.0.7          bind one local interface address
  dsh --profile web --public-url https://app.example/ui/ --trusted-host app.example
                                             advertise a prefix-stripping HTTPS proxy entry and admit its authority
  dsh --profile web --tls-cert ./server-chain.pem --tls-key ./server-key.pem
                                             serve HTTPS with an existing certificate and key

Environment:
  DSH_WEB_HOST   default bind address when --host is absent; same rules as --host
`)
}

/**
 * Parse and provide the Web invocation as an ordinary Cordis service. The
 * command's action publishes the flags this invocation named. Invalid flags,
 * including an unpaired TLS certificate or key, are usage errors; rejection
 * and `--help` provide no service. An invocation that names no `--host` gets
 * the resolved default bind address instead of leaving the value unset.
 * @param ctx - plugin context carrying the command line.
 */
export function apply(ctx: Context): void {
  const program = webCommand()
  program.action(() => {
    const options = program.opts<WebOptions>()
    let host: string
    if (options.host !== undefined) {
      if (isWildcardHost(options.host)) {
        program.error(`error: --host ${options.host} is an unspecified (wildcard) address, which is not supported: binding every interface would expose remote code execution to the network; bind one concrete IPv4 or IPv6 address instead`)
      }
      host = options.host
    } else {
      host = resolveDefaultBindHost(process.env, networkInterfaces()).host
      if (isWildcardHost(host)) {
        program.error(`error: ${WEB_HOST_ENV} ${host} is an unspecified (wildcard) address, which is not supported: binding every interface would expose remote code execution to the network; set one concrete IPv4 or IPv6 address instead`)
      }
    }
    if (options.port !== undefined && !/^\d+$/.test(options.port)) {
      program.error(`error: --port must be a number, got ${JSON.stringify(options.port)}`)
    }
    let tls: TlsConfig | undefined
    if (options.tlsCert !== undefined && options.tlsKey !== undefined) {
      tls = { certFile: options.tlsCert, keyFile: options.tlsKey }
    } else if (options.tlsCert !== undefined || options.tlsKey !== undefined) {
      program.error('error: --tls-cert and --tls-key must be supplied together')
    }
    if (options.publicUrl !== undefined) {
      try {
        parsePublicUrl(options.publicUrl, '--public-url')
      } catch (error) {
        program.error(`error: ${(error as Error).message}`)
      }
    }
    ctx.provide(WEB_STARTUP_SERVICE, {
      openBrowser: options.open,
      host,
      ...options.port !== undefined && { port: Number(options.port) },
      ...options.publicUrl !== undefined && { publicUrl: options.publicUrl },
      ...tls !== undefined && { tls },
      trustedHosts: options.trustedHost ?? [],
    } satisfies WebStartupValues)
  })
  parseCmdline(ctx, program)
}
