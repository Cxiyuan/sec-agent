## 深瞳 · TLS 指纹采集开关
##
## 收录清单（**只收 BSD-3-Clause，可随产品分发**）：
##   - JA3 / JA3S：salesforce/ja3（BSD-3-Clause）→ 落 `ssl.log` 的 `ja3` / `ja3s` 字段
##   - JA4：FoxIO ja4-zeek-scripts 的 BSD 子集（TLS 客户端指纹）→ 落 `ssl.log` 的 `ja4` 字段
##
## 未收录（**故意**）：JA4S / JA4H / JA4L / JA4LS / JA4T / JA4TS / JA4D / JA4SSH / JA4X
##   这些属 FoxIO License 1.1（仅非商业用途、专利待批）。本产品会对外售卖/托管给客户，
##   按该许可证的 FAQ，这种用法需要先拿 FoxIO 的 OEM 授权，所以脚本不进仓库。
##   将来若拿到授权，把脚本放进 `vendor/ja4/` 下自行 @load 即可，本文件不用改。
##
## 关掉指纹采集：在 `local.zeek` 里把 `@load ./shentong-fingerprints` **之前**加一行
##   redef ShentongFingerprints::ja3_enabled = F;
##   redef ShentongFingerprints::ja4_enabled = F;
## （两个开关都是编译期常量，@if 只在加载那一瞬间生效，加载之后再 redef 没用。）

module ShentongFingerprints;

export {
  option ja3_enabled: bool = T;
  option ja4_enabled: bool = T;
}

@if (ShentongFingerprints::ja3_enabled)
  @load ./vendor/ja3
@endif

@if (ShentongFingerprints::ja4_enabled)
  @load ./vendor/ja4
@endif
