## 深瞳自建加载器（本文件不是上游文件）
##
## 上游包根 zeek/__load__.zeek 的职责是：先声明空的 FINGERPRINT::Info 记录与 connection$fp 字段
## （Zeek 9 的 base 里没有 FINGERPRINT 模块，必须由包自己声明），再按各方法的开关决定 @load 谁。
## 我们只收录 BSD-3-Clause 的 JA4 本体（TLS 客户端指纹），
## 不含 JA4S / JA4H / JA4L / JA4LS / JA4T / JA4TS / JA4D / JA4SSH / JA4X（FoxIO License 1.1，非商业），
## 所以这里固定只加载 ./ja4，没有别的开关。
##
## 许可证：JA4 本体为 BSD-3-Clause（见 ../LICENSE-JA4.txt）。

module FINGERPRINT;

export {
  type Info: record {};
}
redef record connection += { fp: FINGERPRINT::Info &optional; };

@load ./config
@load ./ja4
