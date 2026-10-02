# Zeek 指纹脚本（vendor）

这里放**可随产品分发**的第三方 Zeek 指纹脚本。挑脚本的第一原则是许可证：深瞳会作为产品售卖/托管给客户，
只有宽松许可证（BSD-3-Clause 一类）的脚本才能进仓库。

放在 `site/` 下面是有意的：`ndr/zeek/Dockerfile` 只 `COPY site/ /usr/local/zeek/share/zeek/site/`，
所以 `site/` 里的相对 `@load`（如 `shentong-fingerprints.zeek` 里的 `@load ./vendor/ja3`）在镜像里照样成立。

## ja3/ —— JA3 / JA3S（TLS 客户端 / 服务端指纹）

- 上游：<https://github.com/salesforce/ja3>，commit `502cc6395811c54743b0561419d61900a6df3ff7`（2025-05-01）
- 许可证：**BSD-3-Clause**（`ja3/LICENSE.txt` 为上游原文）
- 逐字收录：`ja3.zeek`、`ja3s.zeek`、`zkg.meta`、`LICENSE.txt`
- **自建文件**：`ja3/__load__.zeek` —— 上游的同名文件还会 `@load ./intel_ja3.zeek`
  （把指纹接进 Zeek Intel 情报框架、另开 `ja3sfp` 流），本项目不用情报框架，故只加载真正写字段的两个脚本。
- 产出：`ssl.log` 增加 `ja3`（客户端）、`ja3s`（服务端）两列。
- 注：两个脚本各自 `Log::create_stream` 了 `tlsfp` / `ja3sfp` 两个独立流，但**都没装写入口**
  （没有任何 `Log::write`），所以不会多出日志文件，Filebeat 也就不会采到它们。

## ja4/ —— JA4（TLS 客户端指纹，**只有 BSD 的那一个方法**）

- 上游：<https://github.com/FoxIO-LLC/ja4-zeek-scripts>，commit `8bf9feca52790ae8c926c6a8d79a3547ac19541a`（2026-08-14）
- 许可证：**只有 JA4 本体是 BSD-3-Clause**（`ja4/LICENSE-JA4.txt` 为上游原文）；该仓库其余方法全是
  `FoxIO License 1.1`（仅非商业用途、专利待批）。
- 逐字收录：`ja4/ja4/{__load__.zeek,helpers.zeek,main.zeek}`、`ja4/utils/{common.zeek,ssl-consts.zeek}`、`LICENSE-JA4.txt`
- **自建文件**：`ja4/__load__.zeek`（声明 `FINGERPRINT::Info` 与 `connection$fp`，只 `@load ./ja4`）、
  `ja4/config.zeek`（只保留 `delimiter`、`JA4_raw` 两个选项）。
  上游包根还会按开关加载 JA4S/JA4H/JA4L/JA4SSH/JA4T/JA4D 并在 `config.zeek` 里声明它们的开关，这些都不在仓库里。
- 产出：`ssl.log` 增加 `ja4` 一列（`JA4_raw` 打开时再加 `ja4_o`/`ja4_r`/`ja4_ro`）。
- 注：脚本里 `Log::create_stream(FINGERPRINT::JA4::LOG, … $path="fingerprint_ja4")` 的**写入口是注释掉的**，
  所以同样不会多出 `fingerprint_ja4.log`。

## 为什么不收录 JA4+（JA4S/JA4H/JA4L/JA4T/JA4SSH/JA4D/JA4X）

上游 FAQ 的原话大意：JA4+ 对「学术研究」与「公司内部拿它保护自己」宽松，但**厂商把 JA4+ 当作产品功能出售、
或托管给客户、甚至只是用它给付费客户提供价值，都需要先取得 FoxIO 的 OEM 授权**；所有 JA4+ 方法与检测逻辑
还处在专利申请中。深瞳属于「会卖/会托管」的用法，所以这些脚本一律不进仓库。

将来拿到授权后要开启：把对应脚本放到 `ja4/` 下（保持上游目录结构），
在 `ja4/config.zeek` 补回相应 `option`，并在 `ja4/__load__.zeek` 里 `@if` 挂上即可；`site/shentong-fingerprints.zeek` 不用改。
