## 批 2 单测：TLS 指纹 + Zeek 自带策略脚本真的加载并生效。
##
## 依赖 run.sh 把**整棵 site/ 树**（含 vendor/）复制到工作目录：
## shentong-fingerprints 用的是相对 `@load ./vendor/ja3`，只复制 *.zeek 会加载失败。
##
## 断言方式：Zeek 是编译期加载，字段/选项写错本脚本根本编译不过；能跑出 PASS 就说明
## 「脚本加载成功 + 字段/开关名字对得上」。真正的指纹计算（ja4 值）由容器实机测试覆盖
## （见 docs/ndr-redesign.md 第 10 期），这里不造 pcap。

@load base/frameworks/notice
@load ./shentong-fingerprints
@load ./shentong-policies

global fails: count = 0;

function check(tag: string, ok: bool) {
    if ( ok ) print fmt("PASS %s", tag);
    else { print fmt("FAIL %s", tag); fails += 1; }
}

event zeek_done() {
    local info: SSL::Info;
    info$ja4 = "t13d301200_1d37bd780c83_ecd0401ec68b";
    check("ssl.log has ja4 field", info$ja4 == "t13d301200_1d37bd780c83_ecd0401ec68b");
    check("ja4 delimiter default _", FINGERPRINT::delimiter == "_");
    check("ja4 raw form off by default", ! FINGERPRINT::JA4_raw);
    check("ja3 switch on by default", ShentongFingerprints::ja3_enabled);
    check("ja4 switch on by default", ShentongFingerprints::ja4_enabled);
    check("stats policy loaded (5min)", Stats::report_interval == 5min);
    check("notice stream disabled", Notice::LOG !in Log::active_streams);
    print fmt("FAILS=%d", fails);
}
