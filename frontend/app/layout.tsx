import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "深瞳 · 安全分析智能体",
  description: "安全分析智能体管理后台与驾驶舱",
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
