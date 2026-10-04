/** @type {import('next').NextConfig} */
const nextConfig = {
  // 共享包 @shentong/ui 以 TS 源码形式提供（main 指向 src/index.ts），需转译
  transpilePackages: ["@shentong/ui"],
  async redirects() {
    // `/` → 「总览」（默认落地页）。为什么不用 app/page.tsx 里的 `redirect()`：
    // 在 App Router 里对静态页调 `redirect()`，Next 把它烘成 **错误外壳**（
    // `<html id="__next_error__">` + `NEXT_REDIRECT` 摘要，靠客户端 JS 跳），
    // 实机实测：回 307 **但不带 Location 头**，还被 `s-maxage=31536000` 缓存一年 ——
    // 浏览器里碰运气能跳，curl / 健康检查 / 链接检查器看到的就是个坏 307。
    // 写在 next.config 里是服务端级重定向，会老老实实回 `Location: /admin/status`，
    // 不依赖 JS、不进页面缓存。（所以 app/page.tsx 已删除：留着它只能产生坏 307。）
    return [{ source: "/", destination: "/admin/status", permanent: false }];
  },
  async rewrites() {
    // 注意：rewrites 在「构建时」求值（不是运行时），所以这里必须给出正确默认值。
    // compose 里的服务名就是 backend，故默认指向它；如需其它地址，构建时传 BACKEND_URL。
    const api = process.env.BACKEND_URL || "http://backend:8000";
    return [
      {
        source: "/api/:path*",
        destination: `${api}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
