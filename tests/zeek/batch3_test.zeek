## 批 3 单测：HTTP 头采集脚本 + 正文上限脚本（编译期契约）。
##
## 依赖 run.sh 把整棵 site/ 树复制到工作目录并把本文件放到同目录。
## 这里只验证「脚本加载成功 + 常量/字段/函数行为对得上」；真实流量的截断效果由
## zeek/zeek:9.0 容器实测与服务器探针覆盖（见 docs/ndr-redesign.md 第 11 期）。

@load ./shentong-httpbody
@load ./shentong-limits
@load ./shentong-httpheaders

global fails: count = 0;

function check(tag: string, ok: bool) {
    if ( ok ) print fmt("PASS %s", tag);
    else { print fmt("FAIL %s", tag); fails += 1; }
}

event zeek_done() {
    # http.log 新增两个字段（编译期字段存在性）
    local info: HTTP::Info;
    info$req_headers = "HOST: probe\n";
    info$resp_headers = "CONTENT-TYPE: application/json\n";
    check("http.log has req_headers field", info$req_headers == "HOST: probe\n");
    check("http.log has resp_headers field", info$resp_headers == "CONTENT-TYPE: application/json\n");

    # 上限默认值：Zeek 侧与后端 settings 都是 16KB / 64KB
    check("request body limit default 16384", ShentongHTTP::max_body_len == 16384);
    check("response body limit default 65536", ShentongHTTP::max_resp_body_len == 65536);

    # 头截断常量
    check("single header cap 256", ShentongHTTPHeaders::max_header_value_len == 256);
    check("direction header cap 4096", ShentongHTTPHeaders::max_headers_len == 4096);

    # 单头截断：8 字节头名 + 256 字节值 + 换行（Zeek 没有字符串乘法，用循环拼）
    local long = "";
    local k = 0;
    while ( k < 400 ) { long += "A"; k += 1; }
    local one = ShentongHTTPHeaders::append_header("", "X-Long", long);
    check("long header value truncated to 256", |one| == 8 + 256 + 1);

    # 控制字符（换行注入）被替换成占位符
    check("crlf injection neutralized", ShentongHTTPHeaders::clean_header_value("a\x0d\x0ab") == "<binary>");
    check("plain value kept", ShentongHTTPHeaders::clean_header_value("plain") == "plain");

    # 总量封顶：一直加也不会超过 4096
    local fill = "";
    local j = 0;
    while ( j < 200 ) { fill += "B"; j += 1; }
    local acc = "";
    local i = 0;
    while ( i < 100 ) {
        acc = ShentongHTTPHeaders::append_header(acc, "X-Fill", fill);
        i += 1;
    }
    check("total header cap 4096", |acc| == 4096);

    print fmt("FAILS=%d", fails);
}
