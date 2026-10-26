/**
 * xdr-agent-pack — 部署级能力包（只声明启用哪些第一方 dsh 插件）。
 *
 * 这个包**没有运行逻辑**：它存在的意义是把「本项目决定启用的原生能力」写进
 * 一层 bundle patch，跟 xdr-ingest / xdr-ui 一样由镜像 bake、随 profile 激活。
 * 这样启用清单和业务代码分开审阅，也不会散落在部署机的 profile 里。
 *
 * 当前启用：
 * - dsh-time-context：每一步给模型当前时间与耗时（研判时间窗必需）
 * - dsh-tool-schedule：定时复查类工具（schedule_create/list/update/delete），
 *   宿主 dsh-schedule 服务由 dsh-web-app 已提供
 * - 会话检索（dsh-experimental-session-search bundle）在镜像里单独激活，
 *   不在本 patch 里：它是 bundle 层，走 profile.bundles。
 */

/** Cordis function-plugin name。 */
export const name = 'xdr-agent-pack'

/** 没有可执行逻辑：启用清单全在 cordis.patch.yml。 */
export function apply(): void {}
