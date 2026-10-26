# @sec-agent/xdr-ui — 深瞳分析控制台

agent 侧的**运营界面插件**：这不是聊天窗口，是"后台自助分析的工作智能体"的
控制台——`/xdr/ui`，带登录鉴权（默认 admin/admin123）。站点根路径 `/` 直接
跳到这里；dsh 原始会话界面保留在 `/index.html`（只作排障用，不再当默认入口）。

## 为什么不是再开一个聊天窗口

现在的 agent 是无人值守的：NDR 发**门铃** → 领取循环 `claim_tasks` 领工单 →
起分析会话 → 模型用 MCP 工具取证 → `complete_task` 交结论。运营侧要看的
是**这台机器在干什么、干成了什么**，不是再和它聊两句。工作台因此长这样：

| 面板 | 内容 | 数据源 |
|---|---|---|
| 运行总览 | 分析循环开关、在跑/并发上限、门铃与领取/启动/放弃/失败计数、连续错误与最近错误、剩余预算快照、热层/冷库条数、最近 5 条分析 | `xdrIngest.status()/cacheStats()/listAnalyses()` |
| 分析记录 | PG 冷库的历史结论：规则、源 IP、严重度、结论摘要、出现次数、最近出现；分页 + 搜索 + 详情（身份、结论、处置建议、原始 JSON） | `xdrIngest.listAnalyses()/getAnalysis()` |
| 配置 | 运行参数（轮询间隔 / 本机并发 / 单次领取条数）热更新并持久化；连接与凭据状态（NDR MCP 地址与令牌是否配置、门铃令牌、冷库类型、登录账号与密码来源、会话时长）；NDR 控制台与原始会话界面入口 | `xdrIngest.settings()/updateSettings()` + 部署环境缝 |

左侧固定功能菜单（运行总览 / 分析记录 / 配置），无聊天输入框。原始会话界面上
注入一枚「返回控制台」角标（`webserver.tapIndex`，登记式注入，不改 dsh 上游文件）
——控制台是运营视图，会话是取证视图，两者互补。

## 鉴权

- 凭据与 dsh 的 `/login` **同一组环境缝**：`DSH_WEB_AUTH_USER` /
  `DSH_WEB_AUTH_PASSWORD`（缺省 admin / admin123，现场部署默认）。
- 自己签发 `HttpOnly; SameSite=Strict` 会话 Cookie，HMAC-SHA256 签名；
  API 未登录一律 401，页面未登录一律 303 到登录页。
- 密钥寻源：`DSH_WEB_UI_SECRET` → `DSH_WEB_LAUNCH_TOKEN`（部署缝已固化，
  重启不变）→ 进程内随机（每次重启当前登录失效，属可用性损失，启动日志会警告）。
- 与 dsh 的登录互不冒充：同一浏览器里登出工作台不影响原生界面的会话，反之亦然。

## HTTP 契约

| 端点 | 方法 | 说明 |
|---|---|---|
| `{basePath}` | GET | 工作台页（未登录 303 → `{basePath}/login`） |
| `{basePath}/login` | GET/POST | 登录页；POST 表单或 JSON `{user,password}`；成功 303 + Set-Cookie |
| `{basePath}/logout` | POST | 清 Cookie，303 回登录页 |
| `{basePath}/api/overview` | GET | `{available, status, cache}`（数据面不在场时 `available:false`） |
| `{basePath}/api/analyses?limit&offset&q` | GET | `{available, total, entries[]}`，last_seen 降序，limit 钳制 1..200 |
| `{basePath}/api/analyses/{id}` | GET | `{entry}`（完整记录）；404 = 无此 ID |
| `{basePath}/api/wake` | POST | `{accepted}`；分析循环未启用时 accepted=false |
| `{basePath}/api/settings` | GET | `{available, settings{poll_seconds,max_concurrent,claim_limit,store}, meta{...}}`；数据面不在场 `available:false` |
| `{basePath}/api/settings` | POST | JSON 补丁（三个整数字段）；越界/非整数 400，成功 `{ok,persisted,settings}`；数据面不在场 503 |
| `/` | GET | 303 → `{basePath}/`（站点默认入口交给控制台） |

## 配置

| 字段 | 默认 | 说明 |
|---|---|---|
| `basePath` | `/xdr/ui` | 路由基路径（避开 dsh 的 `/api` 与 xdr-ingest 的 `/xdr/ingest`） |
| `user` / `password` | `''`（回落 admin/admin123） | 留空走环境缝，显式配置优先 |
| `secret` | `''`（按上文寻源） | 会话签名密钥 |
| `sessionHours` | 12 | 会话时长 |
| `badge` | true | 原始界面注入「返回控制台」角标 |
| `ndrConsoleUrl` | `''` | NDR 管理台地址，左侧菜单入口；空则隐藏（部署缝 `DSH_WEB_NDR_CONSOLE_URL`） |

## 与 xdr-ingest 的服务缝

xdr-ingest 在 apply 里 `ctx.reflect.provide('xdrIngest', …)` 暴露数据面；本插件
`ctx.reflect.get('xdrIngest', false)` 可选读取（**不写 `inject`**：xdr-ingest
缺席时工作台必须还能打开）。两侧用各自进程内的结构化类型对齐，不跨包 import
——独立 plugin workspace 的 typecheck 先于邻居 build 跑，跨包类型引用会造成
"必须先构建邻居"的门禁顺序耦合。

## 开发

```sh
pnpm typecheck    # tsc --noEmit（CI）
pnpm test         # node --test 本地可跑（零 peer 依赖：只测 ui-auth / html / http 三层）
pnpm run build    # tsc 产出 lib/
```

## 已知限制

- 工作台是**单页面单账号**语义：无多租户、无账号管理页（规划中）；
- `logout` 只清本浏览器 Cookie，不吊销其他端（无服务端会话表——纯签名 Cookie 的
  取舍：停机重启 + 换密钥才是全局会话失效手段）；
- 控制台只写**本机运行参数**；规则/网段/抑制等 NDR 侧配置仍走 NDR 管理台
  （左侧菜单有入口）。登录密码与 MCP 令牌只能改部署环境变量后重启，页面上只
  显示"是否已配置"，不回显密钥；
- `/` 被本插件独占为控制台入口：同一部署里不能再有第二个插件注册 exact `/`。
