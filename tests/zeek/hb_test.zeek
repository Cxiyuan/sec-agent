@load base/protocols/http
@load ./shentong-httpbody

# 单测：把上限压到很小，方便断言截断（标签用 ASCII，Zeek 的 print 会把中文打成 \xNN 转义）
redef ShentongHTTP::max_body_len = 8;
redef ShentongHTTP::max_resp_body_len = 6;

global fails: count = 0;

global c1: connection;   # POST：请求/响应分块累加 + 截断
global c2: connection;   # GET：无请求体、有响应体
global c3: connection;   # 含 NUL 的二进制块
global c4: connection;   # UTF-8 中文
global c5: connection;   # PUT 也要采请求体

function init_conn(c: connection, method: string) {
    c$http = HTTP::Info($ts=network_time(), $uid="unit", $trans_depth=1,
        $id=conn_id($orig_h=1.1.1.1, $orig_p=1111/tcp, $resp_h=2.2.2.2, $resp_p=80/tcp),
        $method=method);
}

function req(c: connection, data: string) {
    event http_entity_data(c, T, |data|, data);
}

function resp(c: connection, data: string) {
    event http_entity_data(c, F, |data|, data);
}

function got_body(c: connection): string {
    return c$http?$body ? c$http$body : "<none>";
}

function got_resp(c: connection): string {
    return c$http?$resp_body ? c$http$resp_body : "<none>";
}

function check(tag: string, got: string, want: string) {
    if ( got == want ) {
        print fmt("PASS %s", tag);
    } else {
        print fmt("FAIL %s -> got [%s] want [%s]", tag, got, want);
        fails += 1;
    }
}

event zeek_init() {
    init_conn(c1, "POST");
    req(c1, "hello");
    req(c1, "world");
    resp(c1, "abc");
    resp(c1, "defgh");

    init_conn(c2, "GET");
    req(c2, "hello");
    resp(c2, "ok");

    init_conn(c3, "POST");
    req(c3, "a\x00b");
    resp(c3, "c\x00d");

    init_conn(c4, "POST");
    req(c4, "\xe4\xb8\xad\xe6\x96\x87");
    resp(c4, "\xe4\xb8\xad\xe6\x96\x87");

    init_conn(c5, "PUT");
    req(c5, "12345");
}

# 事件队列在 zeek_init 之后才执行，断言必须放在 zeek_done
event zeek_done() {
    check("req body chunks, cap 8", got_body(c1), "hellowor");
    check("resp body chunks, cap 6", got_resp(c1), "abcdef");
    check("GET has no request body", got_body(c2), "<none>");
    check("GET still has response body", got_resp(c2), "ok");
    check("NUL request body blocked", got_body(c3), "<none>");
    check("NUL response body blocked", got_resp(c3), "<none>");
    check("UTF-8 request body kept", got_body(c4), "\xe4\xb8\xad\xe6\x96\x87");
    check("UTF-8 response body kept", got_resp(c4), "\xe4\xb8\xad\xe6\x96\x87");
    check("PUT captures request body", got_body(c5), "12345");
    print fmt("FAILS=%d", fails);
}
