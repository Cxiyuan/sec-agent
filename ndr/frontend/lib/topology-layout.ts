/**
 * 连接拓扑的排布算法（纯函数，不碰 React / ECharts）。
 *
 * 单独成一个模块有两个原因：
 * 1. 这是**唯一**能出错又看不出来的地方 —— 坐标算歪了，画布上不会报错，只会让节点叠在
 *    一起或者跑出可视区。抽出来之后可以用 node 直接跑一遍断言边界，不依赖浏览器。
 * 2. `traffic-panel.tsx` 已经 700 多行，表格 + 弹窗 + 图表配置挤在一起，加 130 行布局
 *    会彻底读不动。
 *
 * 坐标口径：**画布像素**，左上角是 (0, 0)。渲染侧靠 `series` 四边钉 0 + 四角锚点把
 * ECharts 的 view 坐标系压成 1:1 恒等映射，所以这里算出来的数值就是屏幕位置。
 */

/** 中心以外的一个对端（结构上是 `traffic-panel.tsx` 里 `PeerNode` 的子集） */
export interface TopologyPeer {
  ip: string;
  hostname?: string;
  /** 后端按监控网段判定，恒为布尔；缺字段时按外网处理 */
  internal?: boolean;
  bytes: number;
}

export type NodeKind = "center" | "internal" | "external";

export interface PlacedNode {
  ip: string;
  /** 节点下方标签（有主机名就两行，没有就一行 IP） */
  label: string;
  x: number;
  y: number;
  kind: NodeKind;
  /** 图标框 [宽, 高]：云是 1.43:1，必须按原稿比例配框，否则等比内缩后上下留一条 */
  size: [number, number];
  /** 该节点与中心之间的总流量（字节），只用于 tooltip */
  bytes: number;
}

/**
 * 排布参数（单位：像素）。
 *
 * 画布尺寸变化只影响「行槽 / 列位怎么分」，这几个下限是视觉可读性的底线：
 * 低于 `rowMin` 就开始等比缩图标，低于 `colGap` 标签就互相压住了。
 */
export const TOPO = {
  /** 左右留白：要放得下最外侧节点的半行 IP 标签，否则字会被画布裁掉 */
  padX: 112,
  /** 上下留白 */
  padY: 52,
  /** 同一行相邻节点的最小水平中心距 */
  colGap: 132,
  /** 一行至少要占的垂直空间（图标 48 + 两行标签 + 间隙） */
  rowMin: 98,
  /** 中心服务器图标边长 */
  hubSize: 64,
  /** 对端图标基准边长 */
  nodeSize: 48,
  /**
   * 中心图标之外，上下两翼还要再让开的**垂直净空**（像素）。
   *
   * 由四段组成：中心标签两行约 30 + 标签与图标的 distance 9 + 对端图标半高 24 + 留白 9。
   * 少算这一段，下翼第一行节点的图标会压住中心那两行标签（`.svg` 图标的顶边正好落在字上）。
   */
  hubClear: 72,
  /** 外网（云）图标框的宽高比，与 `bindBox.svg` 的 viewBox 一致 */
  externalAspect: 1462 / 1024,
} as const;

/** 图标缩小系数的下限：再小就分不清是服务器还是云了 */
const MIN_SQUEEZE = 0.55;

/**
 * 把「中心 + 对端」排到画布像素坐标上。
 *
 * 布局口径（2026-10 用户要求）：
 * - **外网对端在上、内网对端在下**，各自向中心方向连线；
 * - 每侧按「先铺满一行，再往外加一行」分槽，行槽等分该侧可用高度 ——
 *   所以节点多时自然铺满，节点少时也不会缩在角落；
 * - 每一行在整条可用宽度上均分（1 个节点就居中），这是"铺满画布"的直接来源。
 */
export function layoutTopology(
  w: number,
  h: number,
  centerIp: string,
  centerHost: string,
  centerBytes: number,
  internal: TopologyPeer[],
  external: TopologyPeer[],
): PlacedNode[] {
  const { padX, padY, colGap, rowMin, hubSize, nodeSize, hubClear, externalAspect } = TOPO;
  const usableW = Math.max(240, w - padX * 2);
  const perRow = Math.max(1, Math.floor(usableW / colGap));

  const rowsUp = external.length ? Math.ceil(external.length / perRow) : 0;
  const rowsDown = internal.length ? Math.ceil(internal.length / perRow) : 0;

  // 中心落点：两侧都有节点 → 正中间（上下对称）；只有一侧 → 中心让到另一侧的边上，
  // 把整块画布留给有节点的那一侧。否则「只有外网」时下半张画布是空的，等于没铺满。
  const cx = w / 2;
  let cy = h / 2;
  if (rowsUp > 0 && rowsDown === 0) cy = h - padY - hubSize / 2;
  if (rowsDown > 0 && rowsUp === 0) cy = padY + hubSize / 2;

  // 两翼可用区间：让开中心图标本体 + 它下面那两行标签 + 对端自己的图标半径
  const clear = hubSize / 2 + hubClear;
  const upTop = padY;
  const upBot = Math.max(upTop + 1, cy - clear);
  const downTop = Math.min(h - padY - 1, cy + clear);
  const downBottom = h - padY;

  const slotUp = rowsUp ? (upBot - upTop) / rowsUp : 0;
  const slotDown = rowsDown ? (downBottom - downTop) / rowsDown : 0;
  const squeeze = Math.max(
    MIN_SQUEEZE,
    Math.min(1, Math.min(rowsUp ? slotUp : Infinity, rowsDown ? slotDown : Infinity) / rowMin),
  );

  const placed: PlacedNode[] = [];

  const pushRow = (nodes: TopologyPeer[], y: number, kind: NodeKind) => {
    if (!nodes.length) return;
    // 同行均分整条可用宽度（1 个节点居中）
    const xs =
      nodes.length === 1 ? [cx] : nodes.map((_, k) => padX + (usableW * k) / (nodes.length - 1));
    nodes.forEach((n, k) => {
      const base = Math.round(nodeSize * squeeze);
      placed.push({
        ip: n.ip,
        label: n.hostname ? `${n.hostname}\n${n.ip}` : n.ip,
        x: xs[k],
        y,
        kind,
        size:
          kind === "external"
            ? [Math.round(base * 1.34), Math.round((base * 1.34) / externalAspect)]
            : [base, base],
        bytes: n.bytes,
      });
    });
  };

  // 外网在上：r=0 是**离中心最近**的一行，越往上越远
  for (let r = 0; r < rowsUp; r++) {
    pushRow(external.slice(r * perRow, (r + 1) * perRow), upBot - slotUp * (r + 0.5), "external");
  }
  // 内网在下：同样 r=0 最靠近中心
  for (let r = 0; r < rowsDown; r++) {
    pushRow(internal.slice(r * perRow, (r + 1) * perRow), downTop + slotDown * (r + 0.5), "internal");
  }

  const hub = Math.round(hubSize * Math.max(0.8, squeeze));
  placed.push({
    ip: centerIp,
    label: centerHost ? `${centerHost}\n${centerIp}` : centerIp,
    x: cx,
    y: cy,
    kind: "center",
    size: [hub, hub],
    bytes: centerBytes,
  });

  return placed;
}
