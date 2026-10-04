# 开发提示词

本项目所有 AI 开发助手必须遵守以下沟通规则。

## 回答规则

1. **一律说大白话**：回答用通俗易懂的中文，不堆术语、不绕弯子。
2. **简要回答**：默认只给结论和关键点，禁止一上来输出一大段细节。
3. **追问才展开**：只有用户主动追问细节时，才允许深入展开讨论。
4. **先干后说**：直接给结果，少铺垫、少废话。

## 构建规则

1. **一切构建/编译只在 GitHub Actions 里做**：镜像构建、代码编译、打包、依赖安装，全部由流水线完成。
2. **禁止本地构建镜像**：`docker build` / `docker compose build` / `docker buildx build` 一律不执行。
3. **禁止本地拉取镜像**：`docker pull` / `docker compose pull`，以及**任何会隐式拉镜像的命令**——
   最典型的是 `docker run <镜像>`（本地没有就会自动拉）。已踩过：本地跑 `sh tests/zeek/run.sh`
   会把 `zeek/zeek:9.0`（751MB）拉进开发机。
4. **禁止本地编译/打包/装依赖**：`npm run build` / `next build` / `go build` / `cargo build` /
   `mvn package` / `pip install`（含升/装新依赖）等。要加依赖就改 `pyproject.toml` / `package.json`，
   由 CI 安装并验证。
5. **本地只做这些**（都不产生构建产物、也不需要拉任何镜像）：
   - 写代码、读代码、`git commit` / `git push`；
   - `ruff` / `pyright` 静态检查；
   - `pytest`（`tests/py`，纯 Python、不依赖 Docker）；
   - 前端 `npx tsc --noEmit`（只做类型检查，不产出 `build`）。
6. **需要 Docker 的测试只在 CI 跑**：`sh tests/zeek/run.sh`（它会拉 `zeek/zeek:9.0` 并在容器里编译
   Zeek 脚本）已列入 CI 的 `test` 作业，**本地不再执行**。同理：任何 `docker run` / `docker compose up`
   形式的验证都交给流水线或部署服务器。
7. 构建结果以流水线为准；本地门禁跑完就把结论写进回复，不要在本机复现构建。

## 例外

- 用户明确要求"详细说明""完整方案""写文档"时，按用户要求展开。
- 报错、风险、安全问题时，可适当多说明一句原因，但仍保持简短。
