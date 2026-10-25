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
  ShieldOff,
  Siren,
  SlidersHorizontal,
  UserRound,
  Waypoints,
} from "lucide-react";

/**
 * 一级导航结构（2026-10 用户定）：**页头承载一级菜单**，侧边栏只是「某个一级菜单里的子页」。
 *
 * 六个一级分区：
 * - 运营中心：可视化仪表 + 状态监控 + 告警聚合（**无侧边栏**）
 * - 分析中心：悬停弹出 → 日志检索（无侧边栏）/ 可视化流量（有侧边栏）
 * - 事件中心：命中事件的检索 / 详情 / 处置（**无侧边栏**，2026-10 从运营中心迁出）
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
  /** 侧边栏的匹配前缀（不填就用 href）：同一组子页共用一个侧边栏时用它，
   *  例如可视化流量的三个视角 `/traffic/outbound|lateral|egress` 共用一份侧边栏。 */
  sidebarMatch?: string;
  /** 侧边栏里的分组小标题（相邻同组只显示一次）。子页多到 8 个时必须分组：
   *  平铺成一条的话，找「配置体检」要逐条读过去。 */
  group?: string;
}

export interface NavSection extends NavItem {
  /** 分区标识（页头 map key） */
  key: string;
  /** 悬停弹出的二级菜单（有它的分区，鼠标停留即展开） */
  dropdown?: NavItem[];
  /**
   * 分区在路径上的归属前缀（不填就用 href）。
   *
   * 为什么需要它：分区的 `href` 只是「点这个一级菜单去哪个子页」，不是归属范围。
   * 配置管理的 href 是 `/config/collect`，如果拿它当归属判断，那么
   * `/config/rules`、`/config/storage` 这些**兄弟页都不属于配置管理** ——
   * 侧边栏整块消失、正文从 ml-60 弹回 ml-0，页头的一级菜单也不再高亮，
   * 看起来像被踢出了这个分区。给一个 `/config` 前缀，8 个子页才都归得回来。
   */
  match?: string;
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
];

const ASSET_ITEMS: NavItem[] = [
  { href: "/assets/discovery", label: "资产发现", desc: "从镜像流量里发现网段内的主机", icon: ScanSearch },
  { href: "/assets/groups", label: "资产分组", desc: "按业务/责任人给资产分组", icon: Boxes },
  { href: "/assets/scan", label: "资产扫描", desc: "对网段内主机做存活与端口探测", icon: Radar },
  { href: "/assets/manage", label: "资产管理", desc: "资产台账：名称、归属、责任人与备注", icon: ClipboardList },
];

const CONFIG_ITEMS: NavItem[] = [
  { href: "/config/collect", label: "采集接入", desc: "抓包网卡与监听参数", icon: Radio, group: "接入与范围" },
  { href: "/config/networks", label: "监控网段", desc: "抓哪些网段 · 中继节点", icon: Network, group: "接入与范围" },
  { href: "/config/rules", label: "检测规则", desc: "内置与自定义规则", icon: SlidersHorizontal, group: "检测与过滤" },
  { href: "/config/filters", label: "过滤规则", desc: "降噪过滤与排除", icon: Filter, group: "检测与过滤" },
  {
    href: "/config/suppressions",
    label: "精准抑制",
    desc: "误报抑制 · 影响面试算 · 撤销",
    icon: ShieldOff,
    group: "检测与过滤",
  },
  { href: "/config/storage", label: "数据存储", desc: "Elasticsearch 与入库管道", icon: Database, group: "存储与对接" },
  { href: "/config/agent", label: "智能体对接", desc: "MCP 取数与摘要推送", icon: BarChart3, group: "存储与对接" },
  { href: "/config/health", label: "配置体检", desc: "逐项核对当前生效值", icon: Settings, group: "诊断与账号" },
  { href: "/config/account", label: "账户", desc: "登录口令与会话", icon: UserRound, group: "诊断与账号" },
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
        // 三个视角共用一份侧边栏：按 `/traffic` 前缀匹配，切到横向/外连也不会丢
        sidebarMatch: "/traffic",
        sidebar: TRAFFIC_ITEMS,
      },
      // 派工队列：单页 + 三个浮层，**无侧边栏**（宽表要整幅）。
      // 归属靠这条 dropdown 的 href 判定（`sectionOf` 会检查下拉项），不需要额外的 `match`。
      {
        href: "/analysis",
        label: "派工队列",
        desc: "客观线索队列 · 结论 · 覆盖率 · 预算",
        icon: ClipboardList,
      },
    ],
  },
  {
    key: "events",
    href: "/events",
    label: "事件中心",
    desc: "命中事件 · 检索 · 详情 · 处置",
    icon: Siren,
    match: "/events",
  },
  {
    key: "assets",
    href: "/assets/discovery",
    label: "资产中心",
    desc: "资产发现 · 分组 · 扫描 · 管理",
    icon: Boxes,
    // 四个子页都以 /assets 归属（理由见 NavSection.match）
    match: "/assets",
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
    // 8 个二级页共用一个常驻侧边栏（理由见 NavSection.match）
    match: "/config",
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

/** 分区的归属前缀：`match` 优先，其次 href */
function sectionRoot(section: NavSection): string {
  return section.match ?? section.href;
}

/** 子项的归属前缀：`sidebarMatch` 优先，其次 href（与 sidebarOf 的判定保持同一口径） */
function itemRoot(item: NavItem): string {
  return item.sidebarMatch ?? item.href;
}

/** 当前路径属于哪个一级分区（找不到返回 null） */
export function sectionOf(pathname: string): NavSection | null {
  for (const section of NAV_SECTIONS) {
    if (inPath(pathname, sectionRoot(section))) return section;
    // 下拉项也要按 sidebarMatch 判：可视化流量三个视角共用一份侧边栏，
    // 只看 href 的话横向/外连两个视角会「不属于任何分区」，页头不高亮。
    for (const item of section.dropdown ?? []) {
      if (inPath(pathname, itemRoot(item))) return section;
    }
  }
  // 运营中心的附属页（攻击链还原）也是"运营中心"的语境，但不要侧边栏
  if (inPath(pathname, "/chain")) return NAV_SECTIONS[0];
  return null;
}

/** 当前页面自己的侧边栏（没有就返回空数组 = 不显示侧边栏） */
export function sidebarOf(pathname: string): NavItem[] {
  for (const section of NAV_SECTIONS) {
    if (section.sidebar && inPath(pathname, sectionRoot(section))) return section.sidebar;
    for (const item of section.dropdown ?? []) {
      if (item.sidebar && inPath(pathname, itemRoot(item))) return item.sidebar;
    }
  }
  return [];
}

/** 侧边栏属于哪个分区（侧边栏顶部要写「配置管理」这类分区名）；没有侧边栏返回 null */
export function sidebarSectionOf(pathname: string): NavSection | null {
  return sidebarOf(pathname).length ? sectionOf(pathname) : null;
}

/** 一级菜单是否高亮：分区本身命中，或它下拉里的某项命中 */
export function sectionActive(pathname: string, section: NavSection): boolean {
  if (inPath(pathname, sectionRoot(section))) return true;
  return (section.dropdown ?? []).some((item) => inPath(pathname, itemRoot(item)));
}
