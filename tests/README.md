# tests/ —— 回归测试（进 CI，不靠手工）

这一层是为了解决一个老问题：**能过 CI 却上线才炸**的错（脚本把 BPF 过滤器当文件名、
Filebeat 配置键名不对、类型判定兜底成 conn……）。现在分成三块：

## 1. Python 回归（`tests/py`）

两个栈的包都叫 `app`（`ndr/backend/app`、`agent/backend/app`），同一个进程里没法同时 import，
所以用 `--stack` 选一个栈来跑，**两个栈各跑一遍**：

```sh
.venv/bin/python -m pytest tests/py --stack=ndr -q
.venv/bin/python -m pytest tests/py --stack=agent -q
```

| 文件 | 覆盖 |
| --- | --- |
| `test_log_types.py` | 类型规范化/分类/`is_detectable` 判定矩阵（含 Wazuh 不受闸门约束） |
| `test_normalizer_fields.py` | 类型判定、`raw.log_type`/`raw.source_file` 自解释字段、XFF→`real_client_ip`、响应体截断 |
| `test_xff_respbody.py` | 代理头各种形态（proxied/RFC7239/裸头/IPv6+端口/非法值）、规则命中、画像取真实客户端 |
| `test_stack_consistency.py` | **两侧一致性**：子进程分别加载两侧，逐字段比对（只改一侧会在这里炸） |
| `test_filebeat_yml.py` | 采集配置形状：filestream 路径、排除名单、文件名→类型 JS、`queue.disk`、Redis 输出 |

样本在 `samples.py`（字段名取自实机 `/logs/*.log`），含"没有 `log_type` 的旧文档"
这条只能靠猜的路径。

## 2. Zeek 脚本单测（`tests/zeek`）

```sh
sh tests/zeek/run.sh          # 默认 zeek/zeek:9.0，与 ndr/zeek/Dockerfile 的 ZEEK_BASE 一致
```

在官方 Zeek 容器里把 `ndr/zeek/site/*.zeek` 拷进去跑 `hb_test.zeek`：
请求/响应体分块累加与截断、GET 无请求体但有响应体、NUL 二进制拦截、UTF-8 放行。
Zeek 脚本是编译期加载的，语法/字段错误只有真跑一次才会暴露。
脚本输出以 `FAILS=0` 为通过标记（Zeek 的 `print` 会把中文打成 `\xNN` 转义，故标签用 ASCII）。

## 3. 质量门（CI 与本地同一套）

```sh
.venv/bin/ruff check ndr/backend/app agent/backend/app tests/py
.venv/bin/pyright ndr/backend/app agent/backend/app tests/py
cd ndr/frontend   && npx tsc --noEmit
cd agent/frontend && npx tsc --noEmit
```

`.venv` 需要 `pytest`、`pyyaml`、`ruff`、`pyright`、`pydantic`、`pydantic-settings`、`sqlalchemy`
（后端依赖的完整清单在各 `backend/pyproject.toml`；CI 里按清单装）。
