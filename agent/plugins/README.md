# plugins/ — XDR 自研 dsh 插件

本目录存放**我们为 XDR 项目开发的 dsh 插件包**，与上游 dsh 源码（`agent/dsh/`）物理分离。

## 目录约定

- 一个插件一个子目录，例如 `plugins/xdr-tools/`、`plugins/xdr-memory/`。
- 每个插件是自包含的包：自己的 `package.json`（`dsh.bundle` 字段指向组合用的
  `cordis.patch.yml`）、`src/`、`README.md`。
- 插件逻辑通过 Cordis 服务注册挂进 dsh（工具注册 `ctx.tools`、记忆域
  `ctx.storageDomain`、定时任务 `ctx.schedule`/`ctx.jobs`、Web UI `client-ui` 等），
  **不改 `agent/dsh/` 内的任何上游文件**。

## 挂载方式（首个插件落地时接线）

以 dsh 的 out-of-tree plugin 形态安装：经 plugin manager 安装，或在项目 profile
的 `cordis.patch.yml` 里以 bundle 行挂载。届时同步补 CI 任务
（install → typecheck → lint → build）与本目录的 workspace 配置。

## 当前状态

- **`xdr-ingest/` 已落地（首个插件）**：NDR 摘要 webhook → 事件分析 ID（内容派生、
  跨窗口同类判据）→ 分析缓存（命中复用计数，未命中才分析）。详见其 README。
- 规划中：`xdr-memory`（案件记忆域）、`xdr-triage`（定时分诊）、`xdr-ui`（运营页面）。
