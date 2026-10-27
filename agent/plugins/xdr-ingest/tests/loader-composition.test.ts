/**
 * Real-composition proof: Loader reads a test-only cordis.yml, starts the real
 * web server and tool registry, activates xdr-ingest, serves its HTTP route,
 * executes a model-visible script-library tool, then removes tools on disposal.
 */

import { strict as assert } from 'node:assert'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { afterEach, test } from 'node:test'
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/cordis-plugin-loader'
import type {} from '@deepseek-ai/dsh-host-webserver'
import type {} from '@deepseek-ai/dsh-tools'

const SCRIPT_TOOLS = [
  'find_analysis_scripts',
  'get_analysis_script',
  'save_analysis_script',
]

let root: string | undefined
let context: Context | undefined

afterEach(async () => {
  await context?.fiber.dispose()
  context = undefined
  if (root !== undefined) await rm(root, { recursive: true, force: true })
  root = undefined
})

test('test-only cordis.yml loads xdr-ingest through Loader and disposes its tools', async t => {
  const imports = Promise.all([
    import('@deepseek-ai/cordis'),
    import('@deepseek-ai/cordis-plugin-include'),
    import('@deepseek-ai/cordis-plugin-loader'),
    import('@deepseek-ai/dsh-system-prompt'),
    import('@deepseek-ai/dsh-tools'),
    import('@deepseek-ai/dsh-host-webserver'),
    import('@deepseek-ai/dsh-llm'),
  ])
  let deps: Awaited<typeof imports>
  try {
    deps = await imports
  } catch (error) {
    if (error instanceof Error && error.message.includes("Cannot find package '@deepseek-ai/")) {
      t.skip('Loader-composition dependencies are installed and exercised by CI')
      return
    }
    throw error
  }
  const [cordis, includeModule, loaderModule, systemPromptModule, toolsModule, webServerModule, llmModule] = deps
  const { Context } = cordis
  const Include = includeModule.default
  const Loader = loaderModule.default
  const SystemPrompt = systemPromptModule.default
  const ToolRuntime = toolsModule.default
  const WebServer = webServerModule.default
  const ToolCallId = llmModule.ToolCallId
  const XdrIngest = await import('../src/index.ts')
  assert.equal('default' in XdrIngest, false, 'function plugin must retain its named exports')
  root = await mkdtemp(join(tmpdir(), 'xdr-ingest-loader-'))
  const configPath = join(root, 'cordis.yml')
  await writeFile(configPath, [
    "- name: '@deepseek-ai/dsh-system-prompt'",
    "- name: '@deepseek-ai/dsh-tools'",
    "- name: '@deepseek-ai/dsh-host-webserver'",
    '  config:',
    '    host: 127.0.0.1',
    '    port: 0',
    "- id: xdr-ingest",
    "  name: '@sec-agent/xdr-ingest'",
    '  config:',
    '    token: loader-smoke-token',
    "    pgUrl: ''",
    "    mcpToken: ''",
    '    pruneIntervalMinutes: 60',
    '    scriptMaxCodeBytes: 1024',
    '',
  ].join('\n'))

  context = new Context()
  context.baseUrl = pathToFileURL(root).href + '/'
  await context.plugin(Loader)
  context.loader.builtins.include = Include
  const modules = new Map<string, unknown>([
    ['@deepseek-ai/dsh-system-prompt', SystemPrompt],
    ['@deepseek-ai/dsh-tools', ToolRuntime],
    ['@deepseek-ai/dsh-host-webserver', WebServer],
    ['@sec-agent/xdr-ingest', XdrIngest],
  ])
  Object.assign(context.loader, {
    internal: {
      version: 'v2',
      async import(specifier: string) {
        const module = modules.get(specifier)
        if (module === undefined) throw new Error(`unexpected Loader import: ${specifier}`)
        return module
      },
    },
  })
  await context.loader.create({
    name: 'cordis:include',
    config: { path: pathToFileURL(configPath).href },
  })
  await context.loader.await()

  const tools = context.tools
  const names = tools.schemas().map(schema => schema.name)
  for (const name of SCRIPT_TOOLS) assert.ok(names.includes(name), `${name} must be model-visible`)

  const response = await fetch(`${context.webServer.getOrigin()}/xdr/ingest/ping`, {
    headers: { authorization: 'Bearer loader-smoke-token' },
  })
  assert.equal(response.status, 200)
  assert.equal(await response.text(), 'ok')

  const saved = await tools.execute({
    signal: new AbortController().signal,
    callId: ToolCallId('loader-save-script'),
    name: 'save_analysis_script',
    arguments: {
      name: 'loader_smoke_script',
      scenario: 'Loader composition test: use for a smoke check',
      code: 'printf smoke',
      variables: { TARGET: { description: 'input target', default: 'example' } },
      tags: ['smoke'],
    },
  })
  assert.equal(saved.isError, false)
  const savedText = saved.content.find(part => part.type === 'text')
  assert.ok(savedText?.type === 'text')
  assert.equal(JSON.parse(savedText.text).ok, true)

  const found = await tools.execute({
    signal: new AbortController().signal,
    callId: ToolCallId('loader-find-script'),
    name: 'find_analysis_scripts',
    arguments: { query: 'smoke check' },
  })
  assert.equal(found.isError, false)
  const foundText = found.content.find(part => part.type === 'text')
  assert.ok(foundText?.type === 'text')
  assert.equal(JSON.parse(foundText.text).scripts[0].name, 'loader_smoke_script')

  await context.fiber.dispose()
  assert.equal(
    tools.schemas().some(schema => SCRIPT_TOOLS.includes(schema.name)),
    false,
    'disposing the Loader composition must unregister all script tools',
  )
  context = undefined
})
