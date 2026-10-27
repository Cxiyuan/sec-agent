# @sec-agent/xdr-ingest — NDR 门铃派工 + 智能体记忆插件

> **旧摘要契约已降级（2026-10）**：`/digests` 端点保留为**回滚专用**——新架构下
> NDR 只按门铃、由智能体按预算领取工单；只有把 NDR 侧 `analysis.enabled=false`
> 才会恢复摘要推送。日常不会有流量走到这里。

插件当前主路径是 NDR **只发门铃和客观线索**，智能体按预算领任务、自选取证数据与分析范围；
NDR 不判断事件是不是攻击。`/digests` 与 `EA-` 摘要缓存是旧契约回滚专用，不是日常分析路径。

新派工路径下，插件在智能体侧保存两类记忆：同类现象的分析结论（命中则不再起会话，直接交回），
以及可按场景检索、带变量说明的分析脚本。NDR 只保存任务元数据和智能体提交的结果。

无人值守分析默认继承 DSH「系统 → 模型接入」当前选择的服务商与模型；只有在插件配置里明确填写 `provider` 或 `model` 时才覆盖对应值，代码不固定模型厂商。

## 派工闭环与智能体记忆

NDR 只用客观统计挑线索，派发任务元数据；智能体自行决定调查问题、数据源、查询工具和时间范围。`kind`、`hint`、`strength` 与时间窗只说明任务来源和客观信息，不是结论或强制查询计划。

同类现象结论在智能体侧 PostgreSQL 表 `xdr_ingest_task_result` 保存。身份由 `kind`、对象类型、对象、特征组成；规则命中还需要 NDR 下发的稳定内容身份，区分不同目标、端口与事件类型。有效期默认 24 小时，只有 `terminal_reason=concluded` 的可信结论可复用；可疑、未查完、线索变强和过期结果会重新分析。命中复用时不创建会话，插件直接向 NDR 交回带来源标记的旧结论，不重用旧会话的证据引用。

分析脚本保存在 `xdr_ingest_script`，模型可以按场景检索、读取完整脚本、保存新版本并记录变量说明。同名覆盖必须显式确认；每个脚本正文默认最多 64 KiB。脚本库不会自动执行代码，智能体复用前仍须检查脚本并自行决定是否运行。

两类记忆共用 `pgUrl`（默认读取 `XDR_INGEST_PG_URL`）。Node `pg` 连接串不能带 SQLAlchemy 的 `+psycopg` 后缀；格式为 `postgresql://user:password@host:5432/database`。未配置 PG 时退化为进程内存，重启后结论与脚本都会丢失。

旧摘要推送及 `EA-` 两级缓存只用于回滚，不属于门铃派工的主路径。

## HTTP 契约（对齐 ndr/backend/app/detector/push.py）

| 端点 | 方法 | 说明 |
|---|---|---|
| `{basePath}/digests` | POST | 旧摘要契约，回滚专用；日常只接收门铃 |
| `{basePath}/ping` | GET | NDR 连通性自检 |
| `{basePath}/status` | GET | 分析循环、结论复用计数、已注册脚本工具名与存储类型 |
| `{basePath}/stats` | GET | 旧摘要缓存的分层规模与计数 |

旧摘要端点的响应语义与 NDR 重试分类对齐：

- 鉴权失败 / 载荷坏 / 超限 → **4xx**（NDR 判永久失败，立刻暴露配置错误，不空转）
- 内部分析出错 → **500**（NDR 稍后重推整批；判重缓存幂等，重推零副作用）
- 内容无法识别的单条 → 200 回执里逐条标注 `rejected`（其余照常处理）

仅回滚旧摘要路径时，NDR `system_config` 的 `agent_push.params` URL 才指向
`http://<agent-host>:<dsh 端口>/xdr/ingest/digests`，token 与插件 `token` 一致。

## 配置

| 字段 | 默认 | 说明 |
|---|---|---|
| `basePath` | `/xdr/ingest` | 路由基路径（刻意避开 dsh 的 `/api` 前缀） |
| `token` | 必填 | Bearer token；留空插件**拒绝加载**（不收无鉴权的安全事件） |
| `maxBodyBytes` | 4 MiB | 请求体上限 |
| `resultTtlHours` | 24 | 旧摘要判重缓存有效期 |
| `pgUrl` | `''`（读 `XDR_INGEST_PG_URL`） | 摘要回滚缓存、智能体结论和脚本共用的 PG 连接串；留空 = 都只在内存保存 |
| `hotMaxEntries` | 5000 | 旧摘要缓存热层容量上限 |
| `hotThreshold` | 2 | 旧摘要记录晋升热层的出现次数门槛 |
| `warmupLimit` | 1000 | 旧摘要缓存启动预热条数 |
| `pruneIntervalMinutes` | 60 | 摘要回滚缓存与智能体结论过期清理周期 |
| `taskReuseTtlHours` | 24 | 同类现象结论复用有效期（从上次真实分析起算；0 = 关闭） |
| `taskReuseStrengthDelta` | 0.15 | 新线索强度高出多少就必须重查 |
| `scriptMaxCodeBytes` | 65536 | 单条脚本正文上限（字节） |
| `scriptMaxResults` | 5 | `find_analysis_scripts` 默认返回条数 |
| `provider` / `model` | `''` | 留空继承 DSH 系统里的当前默认选择；填写后覆盖对应字段 |

## 安装与挂载

```sh
dsh plugin install file:/path/to/agent/plugins/xdr-ingest
# 或在 profile 依赖里声明 file: 路径；bundle patch（cordis.patch.yml）自动生效
```

- `file:` 会把包快照进 profile 自带 store，profile 目录可随意搬迁（容器
  bake → 卷即此形态）；`link:` 按相对路径建 symlink，profile 一搬家就悬空，
  仅适合同机原位开发。
- patch 行必须是 `- insert:` + `name`（可解析包名）才能真正把插件挂进
  Loader；只有 `id` + `config` 的补丁只能改「已存在行」的配置，没有行可改时
  整个补丁是空操作——路由不注册，且无任何报错。

token 默认从 `XDR_INGEST_TOKEN` 环境变量读取（bundle patch 里的 `!!js` 缝），
也可在 profile patch / 设置页写定值。PG 连接串默认从 `XDR_INGEST_PG_URL` 读，
生产环境必须配置（否则退化为仅内存冷库，重启丢判重结果）。

## 当前限制

- `pgUrl` 为空或数据库不可用时，脚本库和结论复用退化到进程内存；重启会丢失这两类记忆。
- 脚本库保存智能体生成的代码但不执行代码审查；智能体复用脚本前必须自行检查内容与变量。
- 旧摘要缓存和门铃派工的存储表分别由 `pg-store.ts` 与 `pg-state-store.ts` 管理，使用幂等 DDL，不接入迁移工具。

## 开发

```sh
pnpm install          # CI 里执行（B 方案：本地不装依赖）
pnpm run typecheck    # tsc --noEmit
pnpm test             # node --test（包括 Loader 组合测试；依赖由 CI 安装）
pnpm run build        # tsc 产出 lib/ 与 lib/types/
```

本地不装依赖时，纯逻辑测试可直接跑：
`node --experimental-strip-types --test tests/identity.test.ts tests/store.test.ts tests/tiered-cache.test.ts tests/handler.test.ts`

PG 集成测试（`tests/pg-store.integration.test.ts`、`tests/pg-state-store.integration.test.ts`）需要真实数据库，设置 `XDR_TEST_PG_URL` 后才会执行；CI 的 agent-plugins job 自带 postgres service。

## 运行参数（工作台可改）

`settings.ts` 定义三个可热更新的旋钮——定时轮询间隔、本机并发上限、单次领取条数
（范围与 Config 一致）。保存走 `xdrIngest.updateSettings()`：先校验，再
`ClaimLoop.configure()` 立即生效，最后持久化到 PG 表 `xdr_ingest_settings`
（单行 JSONB；内存冷库则只在进程内）。启动时先读回上次保存的值覆盖 cordis 配置
默认；读不到（或没有 PG）就用配置默认，不影响运行。

租约、队列容量与任务有效期仍在 NDR 侧；NDR 不设领取额度或并发上限。
