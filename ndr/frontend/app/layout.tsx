import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "深瞳 · NDR 检测中心",
  description: "网络检测与响应：规则检测器、采集与配置管理",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="zh-CN" className="dark">
      <body className="min-h-screen bg-background text-foreground antialiased">
        {children}
      </body>
    </html>
  );
}
