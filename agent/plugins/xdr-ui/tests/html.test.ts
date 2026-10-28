import test from 'node:test'
import assert from 'node:assert/strict'
import { workbenchPage } from '../src/html.ts'

/**
 * 控制台页面冒烟：项目组织视图（agent-console.md §二）必须有导航、视图容器与编辑对话框。
 * 项目视图是「接口有、界面无」缺口补齐的产物——这里锁住三件套，防止后续重构静默丢页面。
 */
test('workbench renders the projects view (nav + section + dialog)', () => {
  const html = workbenchPage('/ui')
  assert.match(html, /href="#\/projects" data-view="projects"/, '侧栏导航缺少项目入口')
  assert.match(html, /id="view-projects"/, '缺少项目视图容器')
  assert.match(html, /id="pr-rows"/, '缺少项目列表 tbody')
  assert.match(html, /id="project-dialog"/, '缺少项目编辑对话框')
  assert.match(html, /id="pr-rows"/, '')
  // 项目状态徽章五态（statusTag 的词表来源：agent-console.md §二 界面建议）
  assert.match(html, /auth_mismatch/, '状态映射缺 auth_mismatch')
  assert.match(html, /unreachable/, '状态映射缺 unreachable')
})
