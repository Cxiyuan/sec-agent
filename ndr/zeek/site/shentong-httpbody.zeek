## 深瞳 · HTTP 请求体采集（支撑 Web 深检：注入 / 凭证盗用 / WebShell 上传等）
##
## 做法：HTTP 分析器在传输实体时触发 http_entity_data 事件，逐块给出正文；
##      我们把「请求方向」的正文累积到 HTTP::Info 的自定义字段 body 上，
##      并加上 &log 属性使其写入 http.log。这样一条 http.log 同时含
##      method/uri/user_agent/status_code 与 body，规则可一次性完整匹配。
##
## 安全：① 只取请求方向（响应体不要）；② 硬上限 max_body_len 截断；
##      ③ 跳过含 NUL / C0 控制字符的块（避免把二进制上传内容写进日志），
##         但**必须放行 UTF-8 多字节**，否则中文请求体全丢（见下方 2026-10 实机记录）。

@load base/protocols/http

module ShentongHTTP;

export {
    redef record HTTP::Info += {
        ## 截断后的请求体（供规则匹配；落库前由本项目 normalizer 脱敏口令/Token）
        body: string &log &optional;
    };

    ## 单条请求最多保留的正文长度
    const max_body_len: count = 4096 &redef;
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
    if ( ! is_orig ) return;                      # 只采集请求体
    if ( ! c?$http ) return;

    local method = c$http?$method ? c$http$method : "";
    if ( method == "GET" || method == "HEAD" ) return;

    # 跳过真正的二进制块（上传等），避免日志膨胀：只有出现 NUL、C0 控制字符
    # （tab/CR/LF 除外）或 DEL 才放弃。
    #
    # 2026-10 实机（172.16.196.77）踩到：原判据是 /[^\x09\x0a\x0d\x20-\x7e]/
    # （只放行可打印 ASCII），而 UTF-8 多字节（中文）的字节都 >0x7e，于是
    # **中文请求体整块被丢**，日志里连 body 字段都不出现。同一 POST 路径只换 body
    # 内容的上线对照：
    #   {"probe":"ascii","n":1}   -> http.log 带 body
    #   {"text":"中文请求体"}      -> 无 body 字段
    # 换成本判据后（容器内 zeek 单测四种样本）：ascii/tab_lf/utf8 放行、含 NUL 仍拦。
    if ( /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/ in data ) return;

    if ( ! c$http?$body ) c$http$body = "";
    if ( |c$http$body| >= max_body_len ) return;

    local room = max_body_len - |c$http$body|;
    c$http$body += ( |data| <= room ? data : sub_bytes(data, 1, room) );

    # 达到上限后不再累积（后续块直接丢弃）
    if ( |c$http$body| >= max_body_len ) {
        # 不关闭连接，只停止采集
        return;
    }
}
