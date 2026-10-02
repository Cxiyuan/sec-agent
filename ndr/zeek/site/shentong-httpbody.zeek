## 深瞳 · HTTP 正文采集（支撑 Web 深检：注入 / 凭证盗用 / WebShell 上传等）
##
## 做法：HTTP 分析器在传输实体时触发 http_entity_data 事件，逐块给出正文；
##      请求方向的正文累积到 HTTP::Info 的 body、响应方向累积到 resp_body，
##      两者都加 &log 属性写进 http.log。这样一条 http.log 同时含
##      method/uri/user_agent/status_code 与请求体/响应体，规则可一次性完整匹配。
##
## 安全：① 双向都有硬上限（max_body_len / max_resp_body_len）；
##      ② 跳过含 NUL / C0 控制字符的块（避免把二进制上传、gzip 响应写进日志），
##         但**必须放行 UTF-8 多字节**，否则中文正文全丢（见下方 2026-10 实机记录）；
##      ③ 响应体的**完整字节数**由 Zeek 自带的 response_body_len 记录，与这里
##         的截断无关（normalizer 会落成 resp_body_len）。
##
## 放大上限（改常量即可，写在 site/local.zeek 里）：
##      redef ShentongHTTP::max_resp_body_len = 65536;

@load base/protocols/http

module ShentongHTTP;

export {
    redef record HTTP::Info += {
        ## 截断后的请求体（供规则匹配；落库前由本项目 normalizer 脱敏口令/Token）
        body: string &log &optional;
        ## 截断后的响应体（供规则匹配；响应里同样可能出现令牌/个人信息）
        resp_body: string &log &optional;
    };

    ## 单条请求最多保留的正文长度
    const max_body_len: count = 4096 &redef;
    ## 单条响应最多保留的正文长度（先与请求侧一致，需要时 redef 放大）
    const max_resp_body_len: count = 4096 &redef;
}

## 把一块正文并入累计值，超出上限的部分截断。
function append_chunk(current: string, data: string, limit: count): string {
    if ( |current| >= limit )
        return current;

    local room = limit - |current|;
    return current + ( |data| <= room ? data : sub_bytes(data, 1, room) );
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
    if ( ! c?$http ) return;

    # 跳过真正的二进制块（上传文件、gzip 响应等），避免日志膨胀：只有出现 NUL、
    # C0 控制字符（tab/CR/LF 除外）或 DEL 才放弃。
    #
    # 2026-10 实机（172.16.196.77）踩到：原判据是 /[^\x09\x0a\x0d\x20-\x7e]/
    # （只放行可打印 ASCII），而 UTF-8 多字节（中文）的字节都 >0x7e，于是
    # **中文请求体整块被丢**，日志里连 body 字段都不出现。同一 POST 路径只换 body
    # 内容的上线对照：
    #   {"probe":"ascii","n":1}   -> http.log 带 body
    #   {"text":"中文请求体"}      -> 无 body 字段
    # 换成本判据后（容器内 zeek 单测四种样本）：ascii/tab_lf/utf8 放行、含 NUL 仍拦。
    if ( /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/ in data ) return;

    if ( is_orig ) {
        # 请求方向：GET/HEAD 没有正文要留
        local method = c$http?$method ? c$http$method : "";
        if ( method == "GET" || method == "HEAD" ) return;

        c$http$body = append_chunk(c$http?$body ? c$http$body : "", data, max_body_len);
    } else {
        # 响应方向：body 是截断后的正文，完整字节数看 Zeek 的 response_body_len
        c$http$resp_body = append_chunk(
            c$http?$resp_body ? c$http$resp_body : "", data, max_resp_body_len
        );
    }
}
