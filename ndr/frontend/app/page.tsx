import { redirect } from "next/navigation";

/** 根路径直接落到「总览」（默认落地页）——侧边栏第一项也是它。 */
export default function Home() {
  redirect("/admin/status");
}
