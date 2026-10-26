# @sec-agent/xdr-agent-pack — 部署级能力包

只做一件事：用一层 bundle patch 声明本项目启用的**第一方 dsh 插件**，没有运行逻辑。

## 当前启用

| 行 | 包 | 原因 |
|---|---|---|
| `xdr-time-context` | `@deepseek-ai/dsh-time-context` | 每步注入当前时间/耗时，研判时间窗必需；时区 `Asia/Shanghai`，10 分钟一次 |
| `xdr-tool-schedule` | `@deepseek-ai/dsh-tool-schedule` | 定时复查工具（schedule_create/list/update/delete），配合已启用的宿主 `dsh-schedule` |

会话检索由镜像直接激活 `@deepseek-ai/dsh-experimental-session-search` bundle
（它自带一层 patch，不在本包内重复插行）。

## 加一个能力

1. 确认包已出现在 dsh 安装的依赖里（`agent/dsh/apps/cli/package.json`），否则 Loader 解析不到；
2. 在 `cordis.patch.yml` 的 `insert` 列表追加 `id` + `name`（+ `config`）；
3. CI 重建镜像；容器启动时 profile 指纹变化会自动刷新插件层。

## 为什么不写代码

这些都是原生插件，能力已经完整；包一层 patch 是为了「启用清单可审阅、可随镜像回滚」。
真正属于本项目的逻辑仍在 `xdr-ingest`（取数与派工闭环）和 `xdr-ui`（控制台）。
