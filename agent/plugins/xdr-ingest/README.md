# @sec-agent/xdr-ingest — NDR 摘要接收 + 门铃派工插件

> **旧摘要契约已降级（2026-10）**：`/digests` 端点保留为**回滚专用**——新架构下
> NDR 只按门铃、由智能体按预算领取工单；只有把 NDR 侧 `analysis.enabled=false`
> 才会恢复摘要推送。日常不会有流量走到这里。

首个 XDR 自研 dsh 插件：接收 NDR 检测器 HTTP 推送的聚合摘要，为每条摘要生成
**内容派生的事件分析 ID**，命中分析缓存则直接复用结果并累计次数，未命中才进入
分析——避免重复分析同类事件。

## 事件分析 ID 机制（核心设计）

指标与 NDR 摘要指纹（`ndr/backend/app/detector/fingerprint.py`）采用同一套内容
元组，但**去掉 30 分钟时间桶**：

```
NDR 指纹   = sha256("{rule}|{src}|{桶起点}|{dsts}|{ports}|{etypes}")[:32]   ← 回答"本窗口是否新事件"
事件分析ID = "EA-" + sha256("{rule}|{src}|{dsts}|{ports}|{etypes}")[:32]   ← 回答"跨窗口是否同类事件"
```

- **参与身份的指标**：规则名、源 IP、目标集合（≤20）、端口集合（≤20）、事件类型
  集合（≤10）；排序规范化逐字节对齐 NDR 的 `sorted(str(x))`，日志并排可对照。
- **刻意排除的易变字段**：count、first_seen/last_seen、samples、real_client_ips
  （XFF 随客户端变化）、proxied/conn_states（随路径翻转）、rule_severity。
- **复用有效期**：结果默认 24h（`resultTtlHours` 可调），过期重分析但累计
  occurrences/firstSeen 保留——「同类事件反复出现」这个信号永不丢失。

## 两级缓存：热数据内存、冷数据 PG

冷热分层按「出现频率」自动流转，应用层无感：

```
                 ┌──────────────── 热层（进程内存 LRU）────────────────┐
                 │ 经常出现的 IP/事件模式；occurrences ≥ hotThreshold   │
                 │ 才晋升进来；命中只动内存计数，不打 PG                 │
                 └──────────────────────┬──────────────────────────────┘
   事件进入 → 算分析 ID ──→ 热层未命中 ──→ ┌──────────────── 冷层（PostgreSQL）┐
                                  冷层命中  │ 一切分析结果写穿落盘；           │
                                  且够频繁  │ 「不长分析的 IP」待在库里不占内存；│
                                  → 晋升    │ 热层淘汰 = 降级回写，不丢数据     │
                                            └────────────────────────────────┘
```

- **写穿**：每次分析结果立即 upsert 进 PG——进程重启不丢判重能力，重启后
  同类事件仍走复用（测试 `handler.test.ts` 的 restart 用例锁定该行为）。
- **晋升**：冷命中使 occurrences 达到 `hotThreshold`（默认 2）才进内存；
  首次出现（occurrences=1）只落 PG，不占内存。
- **降级**：热层满时淘汰最久未见记录，回写后移除——淘汰 ≠ 丢弃。
- **预热**：启动时按 occurrences 降序把冷库热数据装进热层（`warmupLimit`）。
- **清理**：`pruneIntervalMinutes` 周期删除两层过期记录。
- **PG 故障降级**：连接失败/查询报错只记日志，摄入不中断——热层继续在
  内存里判重，PG 恢复后由后续写穿补数据；`/stats` 的 `storeKind` 可观测。
- **PG 连接串**（`pgUrl`，默认读 `XDR_INGEST_PG_URL`）：Node 的 `pg` 不吃
  SQLAlchemy 的 `+psycopg` 后缀，形如
  `postgresql://shentong:shentong@localhost:5432/shentong`，与 NDR 侧
  `pg_url` 同一实例同一套账号。留空 = 仅内存冷库（开发兜底，重启即丢）。

## HTTP 契约（对齐 ndr/backend/app/detector/push.py）

| 端点 | 方法 | 说明 |
|---|---|---|
| `{basePath}/digests` | POST | 批量接收 `{"items":[{event_id,fingerprint,digest}]}`，**2xx 即回执** |
| `{basePath}/ping` | GET | NDR 连通性自检（把推送地址的 `/digests` 换成 `/ping` 即此端点） |
| `{basePath}/stats` | GET | 分层规模与计数（热/冷条数、分析/复用/重分析、晋升/降级/预热） |

响应语义与 NDR 重试分类对齐：

- 鉴权失败 / 载荷坏 / 超限 → **4xx**（NDR 判永久失败，立刻暴露配置错误，不空转）
- 内部分析出错 → **500**（NDR 稍后重推整批；判重缓存幂等，重推零副作用）
- 内容无法识别的单条 → 200 回执里逐条标注 `rejected`（其余照常处理）

NDR 侧配置（`system_config` 键 `agent_push.params`）：URL 指向
`http://<agent-host>:<dsh 端口>/xdr/ingest/digests`，token 与插件 `token` 一致。

## 配置

| 字段 | 默认 | 说明 |
|---|---|---|
| `basePath` | `/xdr/ingest` | 路由基路径（刻意避开 dsh 的 `/api` 前缀） |
| `token` | 必填 | Bearer token；留空插件**拒绝加载**（不收无鉴权的安全事件） |
| `maxBodyBytes` | 4 MiB | 请求体上限 |
| `resultTtlHours` | 24 | 分析结果有效期（两层一致） |
| `pgUrl` | `''`（读 `XDR_INGEST_PG_URL`） | 冷库 PG 连接串；留空 = 仅内存冷库 |
| `hotMaxEntries` | 5000 | 热层容量上限，超出降级最久未见记录回冷库 |
| `hotThreshold` | 2 | 晋升热层的出现次数门槛 |
| `warmupLimit` | 1000 | 启动预热装入热层的条数 |
| `pruneIntervalMinutes` | 60 | 过期清理周期 |

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

## 当前限制与后续

- **v0 分析器是启发式**（规则关键词 + 端口广度），P1 换 LLM 分析器（同签名替换）。
- **LLM 分析入口**：P1 经 dsh `webhookRuntime` 为缓存未命中的事件创建分析
  Session——运行时明确不做判重（"rules that need idempotency own it"），本插件的
  分析 ID 缓存正是那道 idempotency 闸门。
- **冷库单表自管理**：DDL 内联在 `pg-store.ts`（`CREATE TABLE IF NOT EXISTS`），
  未接入迁移工具；表结构变更时保持幂等修改即可。

## 开发

```sh
pnpm install          # CI 里执行（B 方案：本地不装依赖）
pnpm run typecheck    # tsc --noEmit
pnpm test             # node --test（零运行时依赖，本地可用 node 22.6+ 直接跑）
pnpm run build        # tsc 产出 lib/ 与 lib/types/
```

本地不装依赖时，纯逻辑测试可直接跑：
`node --experimental-strip-types --test tests/identity.test.ts tests/store.test.ts tests/tiered-cache.test.ts tests/handler.test.ts`

PG 集成测试（`tests/pg-store.integration.test.ts`）需要真实数据库，设置
`XDR_TEST_PG_URL` 后才会执行；CI 的 agent-plugins job 自带 postgres service。

## 运行参数（工作台可改）

`settings.ts` 定义三个可热更新的旋钮——定时轮询间隔、本机并发上限、单次领取条数
（范围与 Config 一致）。保存走 `xdrIngest.updateSettings()`：先校验，再
`ClaimLoop.configure()` 立即生效，最后持久化到 PG 表 `xdr_ingest_settings`
（单行 JSONB；内存冷库则只在进程内）。启动时先读回上次保存的值覆盖 cordis 配置
默认；读不到（或没有 PG）就用配置默认，不影响运行。

配额、租约、保留名额、强度门槛仍在 NDR 侧强制，这里不接受修改。
