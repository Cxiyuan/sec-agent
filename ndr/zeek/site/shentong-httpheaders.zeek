## 深瞳 · HTTP 头值采集（客户端 + 服务端全量头值）
##
## 为什么自己写：Zeek 自带的 HTTP::Info 只挑几个头落成独立字段（host / user_agent /
## referrer / origin / proxied / 认证信息…），policy/protocols/http/header-names.zeek
## 也只记「头名」不记「头值」。规则与调查需要看到完整头值（Cookie、Authorization、
## Content-Type、Set-Cookie、X-Forwarded-* 等），所以这里监听 http_header 事件，
## 把每个头按 "Name: value" 逐行累积进两个 &log 字段。
##
## 上限（硬截断，避免单条日志膨胀；下方都是 &redef，可在 site/local.zeek 里放大）：
##      单个头值 max_header_value_len = 256 字符；单方向累计 max_headers_len = 4096 字符。
##
## 安全：req_headers / resp_headers 是**明文**（Cookie、Bearer / Basic 凭证都会落库），
##      这是既定取舍，见 docs/ndr-collect-plan.md「已接受的风险与取舍」。
##
## 实测（2026-10，zeek/zeek:9.0 容器）：请求头 400 字符被截到 256；累计超 4096 后
##      停止追加；响应头同样按上述规则记账。

@load base/protocols/http

module ShentongHTTPHeaders;

export {
    redef record HTTP::Info += {
        ## 客户端请求头，逐行 "Name: value"（单头 256、总计 4096 封顶）
        req_headers: string &log &optional;
        ## 服务端响应头，同上
        resp_headers: string &log &optional;
    };

    ## 单个头值最多保留的字符数
    const max_header_value_len: count = 256 &redef;
    ## 单方向（请求 / 响应各自）最多保留的头字符总数
    const max_headers_len: count = 4096 &redef;

    ## 头值里的控制字符（含 \r / \n：头值里出现换行会伪造出假头行）换成占位符
    global clean_header_value: function(value: string): string;

    ## 把一个头并入累计值：单头先截断，总量到顶就不再追加（最后一行允许被截断）
    global append_header: function(current: string, name: string, value: string): string;
}

## 头值里的控制字符（含 \r / \n：头值里出现换行会伪造出假头行）换成占位符
function clean_header_value(value: string): string {
    if ( /[\x00-\x1f\x7f]/ in value )
        return "<binary>";
    return value;
}

## 把一个头并入累计值：单头先截断，总量到顶就不再追加（最后一行允许被截断）
function append_header(current: string, name: string, value: string): string {
    if ( |current| >= max_headers_len )
        return current;

    local line = fmt("%s: %s\n", name, sub_bytes(value, 1, |value| <= max_header_value_len ? |value| : max_header_value_len));
    local room = max_headers_len - |current|;
    return current + ( |line| <= room ? line : sub_bytes(line, 1, room) );
}

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if ( ! c?$http ) return;

    local v = clean_header_value(value);
    if ( is_orig )
        c$http$req_headers = append_header(c$http?$req_headers ? c$http$req_headers : "", name, v);
    else
        c$http$resp_headers = append_header(c$http?$resp_headers ? c$http$resp_headers : "", name, v);
}
