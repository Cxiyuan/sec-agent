# plugins/ — XDR 自研 dsh 插件

本目录存放**我们为 XDR 项目开发的 dsh 插件包**，与上游 dsh 源码（`agent/dsh/`）物理分离。

## 目录约定

- 一个插件一个子目录，例如 `plugins/xdr-tools/`、`plugins/xdr-memory/`。
- 每个插件是自包含的包：自己的 `package.json`（`dsh.bundle` 字段指向组合用的
  `cordis.patch.yml`）、`src/`、`README.md`。
- 插件逻辑通过 Cordis 服务注册挂进 dsh（工具注册 `ctx.tools`、记忆域
  `ctx.storageDomain`、定时任务 `ctx.schedule`/`ctx.jobs`、Web UI `client-ui` 等），
  **不改 `agent/dsh/` 内的任何上游文件**。

## 挂载方式

以 dsh 的 out-of-tree plugin 形态安装：经 plugin manager 安装，或在项目 profile
的 `cordis.patch.yml` 里以 bundle 行挂载。届时同步补 CI 任务
（install → typecheck → lint → build）与本目录的 workspace 配置。

容器部署见 `agent/README.md`：镜像里已把插件 bake 进 web profile
（`dsh plugin --profile web add file:/opt/agent/plugins/xdr-ingest`——用 file:
而非 link: 是因为 link: 的 symlink 按相对路径记录，profile 从 bake 目录
种进运行卷后会悬空；file: 快照进 profile 自带 store，可整体搬迁）。

## 当前状态

- **`xdr-ingest/` 已落地（首个插件）**：NDR 摘要 webhook → 事件分析 ID（内容派生、
  跨窗口同类判据）→ 两级缓存（热层内存 LRU + 冷层 PG 写穿，命中复用计数，
  未命中才分析）。详见其 README。
- **`xdr-ui/` 已落地**：登录鉴权的分析工作台 `/xdr/ui`（默认 admin/admin123），
  运行总览 + PG 历史分析记录 + 「立即领取」；`xdr-ingest` 经
  `ctx.reflect.provide('xdrIngest', …)` 供出数据面，本插件可选读取。详见其 README。
- 规划中：`xdr-memory`（案件记忆域）、`xdr-triage`（定时分诊）。
