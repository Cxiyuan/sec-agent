/**
 * 站点强制 HTTPS（自签名证书）——TLS 终结 + HTTP→HTTPS 跳转，反代到同容器里的 Next 应用。
 *
 * 为什么用零依赖的 Node 脚本而不是加一层 nginx：应用与 TLS 在同一容器里，部署面不变
 * （仍是一个前端服务），也不用在多一个代理层里同步配置。证书由入口脚本生成/持久化在 /certs。
 *
 * 环境变量：TLS_CERT / TLS_KEY / TLS_PORT(443) / HTTP_PORT(80) / APP_HOST(127.0.0.1) / APP_PORT(3000)
 */
import fs from "node:fs";
import http from "node:http";
import https from "node:https";

const CERT = process.env.TLS_CERT || "/certs/tls.crt";
const KEY = process.env.TLS_KEY || "/certs/tls.key";
const TLS_PORT = Number(process.env.TLS_PORT || 443);
const HTTP_PORT = Number(process.env.HTTP_PORT || 80);
const APP_HOST = process.env.APP_HOST || "127.0.0.1";
const APP_PORT = Number(process.env.APP_PORT || 3000);

/** 把请求原样转给应用，并补上 X-Forwarded-*（应用侧看协议/来源用） */
function proxy(req, res) {
  const prior = req.headers["x-forwarded-for"];
  const headers = {
    ...req.headers,
    "x-forwarded-proto": "https",
    "x-forwarded-for": `${prior ? `${prior}, ` : ""}${req.socket.remoteAddress || ""}`,
    "x-forwarded-host": req.headers.host || "",
  };
  const upstream = http.request(
    { host: APP_HOST, port: APP_PORT, method: req.method, path: req.url, headers },
    (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode || 502, upstreamRes.headers);
      upstreamRes.pipe(res);
    },
  );
  upstream.on("error", (err) => {
    // 应用还没起来（容器刚启动）时会走到这里：给一句人话，别返回空响应
    res.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
    res.end(`应用未就绪：${err.message}`);
  });
  req.pipe(upstream);
}

const creds = { key: fs.readFileSync(KEY), cert: fs.readFileSync(CERT) };
https.createServer(creds, proxy).listen(TLS_PORT, () => {
  console.log(`[tls] HTTPS 监听 ${TLS_PORT} → http://${APP_HOST}:${APP_PORT}`);
});
http.createServer((req, res) => {
  const host = String(req.headers.host || "").replace(/:\d+$/, "");
  const port = TLS_PORT === 443 ? "" : `:${TLS_PORT}`;
  res.writeHead(308, { Location: `https://${host}${port}${req.url || "/"}` });
  res.end();
}).listen(HTTP_PORT, () => {
  console.log(`[tls] HTTP ${HTTP_PORT} → 308 跳 HTTPS`);
});
