import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { workbenchPage } from '../src/html.ts'

test('workbench 生成的内联脚本必须能通过语法解析', () => {
  const html = workbenchPage('/xdr/ui')
  const start = html.lastIndexOf('<script>') + '<script>'.length
  const end = html.indexOf('</script>', start)
  assert.ok(start > 0 && end > start, '找不到工作台内联脚本')
  const script = html.slice(start, end)
  assert.doesNotThrow(() => new Function(script))
})

test('审计详情里的换行是 JS 转义而不是模板字面量换行', () => {
  const html = workbenchPage('/xdr/ui')
  assert.ok(html.includes("lines.join('\\n')"), '换行必须保持为客户端 JS 的 \\n 转义')
})
