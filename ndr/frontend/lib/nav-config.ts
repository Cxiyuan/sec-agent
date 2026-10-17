import type { LucideIcon } from "lucide-react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Boxes,
  ClipboardList,
  Database,
  Filter,
  GitBranch,
  LayoutDashboard,
  Network,
  Radar,
  Radio,
  ScanSearch,
  Search,
  Settings,
  Share2,
  SlidersHorizontal,
  UserRound,
  Waypoints,
} from "lucide-react";

/**
 * 一级导航结构（2026-10 用户定）：**页头承载一级菜单**，侧边栏只是「某个一级菜单里的子页」。
 *
 * 五个一级分区：
 * - 运营中心：可视化仪表 + 状态监控 + 告警聚合（**无侧边栏**）
 * - 分析中心：悬停弹出 → 日志检索（无侧边栏）/ 可视化流量（有侧边栏）
 * - 资产中心：资产发现 / 资产分组 / 资产扫描 / 资产管理（有侧边栏）
 * - 行为画像：账号会话画像（无侧边栏）
 * - 配置管理：采集、网段、规则、存储…（有侧边栏）
 *
 * 侧边栏挂在**具体页面**上（`NavItem.sidebar`），不是一个分区一种：同一个分区里
 * 「日志检索」没有侧边栏、「可视化流量」有 —— 只有页面级才能表达这件事。
 */

export interface NavItem {
  href: string;
  label: string;
  desc?: string;
  icon?: LucideIcon;
  /** 进入这个页面后，左侧显示的子导航（不填 = 该页面没有侧边栏） */
  sidebar?: NavItem[];
}

export interface NavSection extends NavItem {
  /** 分区标识（页头 map key） */
  key: string;
  /** 悬停弹出的二级菜单（有它的分区，鼠标停留即展开） */
  dropdown?: NavItem[];
}

const TRAFFIC_ITEMS: NavItem[] = [
  {
    href: "/traffic/outbound",
    label: "对外业务流量",
    desc: "公网 → 监控网段的业务访问视角",
    icon: Waypoints,
  },
  {
    href: "/traffic/lateral",
    label: "横向访问流量",
    desc: "监控网段内部之间的连接视角",
    icon: Share2,
  },
  {
    href: "/traffic/egress",
    label: "外连流量",
    desc: "监控网段主动访问出去的视角",
    icon: Radar,
  },
  {
    href: "/topology",
    label: "拓扑发现",
    desc: "转发链路与全量通信的自动拓扑",
    icon: Network,
  },
];

const ASSET_ITEMS: NavItem[] = [
  { href: "/assets/discovery", label: "资产发现", desc: "从镜像流量里发现网段内的主机", icon: ScanSearch },
  { href: "/assets/groups", label: "资产分组", desc: "按业务/责任人给资产分组", icon: Boxes },
  { href: "/assets/scan", label: "资产扫描", desc: "对网段内主机做存活与端口探测", icon: Radar },
  { href: "/assets/manage", label: "资产管理", desc: "资产台账：名称、归属、责任人与备注", icon: ClipboardList },
];

const CONFIG_ITEMS: NavItem[] = [
  { href: "/config/collect", label: "采集接入", desc: "Zeek / 签名引擎 / 归一化链路", icon: Radio },
  { href: "/config/networks", label: "监控网段", desc: "抓包与判定范围", icon: Network },
  { href: "/config/rules", label: "检测规则", desc: "内置与自定义规则", icon: SlidersHorizontal },
  { href: "/config/filters", label: "过滤规则", desc: "排除过滤器与入库过滤", icon: Filter },
  { href: "/config/storage", label: "数据存储", desc: "ES 索引、保留期与磁盘", icon: Database },
  { href: "/config/health", label: "配置体检", desc: "逐项核对运行参数", icon: Settings },
  { href: "/config/agent", label: "智能体对接", desc: "摘要推送与 MCP", icon: BarChart3 },
  { href: "/config/account", label: "账户", desc: "登录口令与会话", icon: UserRound },
];

export const NAV_SECTIONS: NavSection[] = [
  {
    key: "console",
    href: "/console",
    label: "运营中心",
    desc: "可视化仪表 · 状态监控 · 告警聚合",
    icon: LayoutDashboard,
  },
  {
    key: "analysis",
    href: "/logs",
    label: "分析中心",
    desc: "日志检索 · 可视化流量",
    icon: Search,
    dropdown: [
      { href: "/logs", label: "日志检索", desc: "按归一化字段检索 ES 日志（无侧边栏）", icon: Search },
      {
        href: "/traffic/outbound",
        label: "可视化流量",
        desc: "对外业务 / 横向 / 外连三个视角",
        icon: Waypoints,
        sidebar: TRAFFIC_ITEMS,
      },
    ],
  },
  {
    key: "assets",
    href: "/assets/discovery",
    label: "资产中心",
    desc: "资产发现 · 分组 · 扫描 · 管理",
    icon: Boxes,
    sidebar: ASSET_ITEMS,
  },
  {
    key: "behavior",
    href: "/behavior",
    label: "行为画像",
    desc: "账号与会话的长期行为基线",
    icon: Activity,
  },
  {
    key: "config",
    href: "/config/collect",
    label: "配置管理",
    desc: "采集 / 网段 / 规则 / 存储 / 对接",
    icon: Settings,
    sidebar: CONFIG_ITEMS,
  },
];

/** 运营中心里的快捷入口（无侧边栏，用页面内的卡片跳转） */
export const CONSOLE_SHORTCUTS: NavItem[] = [
  { href: "/chain", label: "攻击链还原", desc: "真实请求 IP →（中继…）→ 源站", icon: GitBranch },
  { href: "/traffic/outbound", label: "可视化流量", desc: "对外业务 / 横向 / 外连", icon: Waypoints },
  { href: "/behavior", label: "行为画像", desc: "账号与会话基线", icon: Activity },
  { href: "/config/health", label: "配置体检", desc: "运行参数逐项核对", icon: AlertTriangle },
];

function inPath(pathname: string, href: string): boolean {
  return pathname === href || pathname.startsWith(href + "/");
}

/** 当前路径属于哪个一级分区（找不到返回 null） */
export function sectionOf(pathname: string): NavSection | null {
  for (const section of NAV_SECTIONS) {
    if (inPath(pathname, section.href)) return section;
    for (const item of section.dropdown ?? []) {
      if (inPath(pathname, item.href)) return section;
    }
  }
  // 运营中心的附属页（攻击链还原）也是"运营中心"的语境，但不要侧边栏
  if (inPath(pathname, "/chain")) return NAV_SECTIONS[0];
  return null;
}

/** 当前页面自己的侧边栏（没有就返回空数组 = 不显示侧边栏） */
export function sidebarOf(pathname: string): NavItem[] {
  for (const section of NAV_SECTIONS) {
    if (section.sidebar && inPath(pathname, section.href)) return section.sidebar;
    for (const item of section.dropdown ?? []) {
      if (item.sidebar && inPath(pathname, item.href)) return item.sidebar;
    }
  }
  return [];
}

/** 一级菜单是否高亮：分区本身命中，或它下拉里的某项命中 */
export function sectionActive(pathname: string, section: NavSection): boolean {
  if (inPath(pathname, section.href)) return true;
  return (section.dropdown ?? []).some((item) => inPath(pathname, item.href));
}
