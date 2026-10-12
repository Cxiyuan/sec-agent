/** @type {import('next').NextConfig} */
const nextConfig = {
  // 共享包 @shentong/ui 以 TS 源码形式提供（main 指向 src/index.ts），需转译
  transpilePackages: ["@shentong/ui"],
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
