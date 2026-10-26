/** @type {import('next').NextConfig} */
const nextConfig = {
  // 共享包 @shentong/ui 以 TS 源码形式提供（main 指向 src/index.ts），需转译
  transpilePackages: ["@shentong/ui"],
  async redirects() {
    // 这些 /admin/* 是 2026-10 新信息架构之前的旧地址。页面实现已经整体搬到新地址，
    // 这里只保留为别名，用于兼容历史书签、外部文档与告警模板里写死的链接。
    // 用 permanent: false（307）而非 308：这是内部地址调整，不是对外承诺的永久 URL，
    // 保留以后还能改回或改指向的余地。
    return [
      { source: "/admin/status", destination: "/console", permanent: false },
      { source: "/admin/behavior", destination: "/behavior", permanent: false },
      { source: "/admin/chain", destination: "/chain", permanent: false },
      { source: "/admin/collect", destination: "/config/collect", permanent: false },
      { source: "/admin/networks", destination: "/config/networks", permanent: false },
      { source: "/admin/rules", destination: "/config/rules", permanent: false },
      { source: "/admin/filters", destination: "/config/filters", permanent: false },
      { source: "/admin/storage", destination: "/config/storage", permanent: false },
      { source: "/admin/agent", destination: "/config/agent", permanent: false },
      // 注意这一条名字不同：旧 admin/config 是「配置体检」，新地址叫 /config/health
      { source: "/admin/config", destination: "/config/health", permanent: false },
      { source: "/admin/account", destination: "/config/account", permanent: false },
    ];
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
