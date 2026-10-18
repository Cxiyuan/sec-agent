"use client";

import * as React from "react";
import {
  addEdge,
  Background,
  ConnectionMode,
  Controls,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow,
  type Connection,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Nav } from "@/components/nav";
import {
  resolveIcon,
  TopoNodeView,
  type TopoFlowNode,
  type TopoNodePayload,
} from "@/components/topo-node";
import { Badge, EmptyState, Skeleton } from "@shentong/ui";
import { Button } from "@shentong/ui";
import { Card, CardContent, CardHeader, CardTitle } from "@shentong/ui";
import { Input } from "@shentong/ui";
import {
  ApiError,
  apiFetch,
  errorText,
  type AssetItem,
  type NodeTypeList,
  type TopologyDetail,
  type TopologyItem,
  type TopologyNodeType,
} from "@/lib/api";
import { formatDateTime, statusText } from "@shentong/ui";

const nodeTypes = { topoNode: TopoNodeView };
const GRID = 20;

function uid(prefix: string): string {
  const rnd =
    typeof crypto !== "undefined" && "randomUUID" in crypto
      ? crypto.randomUUID().slice(0, 8)
      : Math.random().toString(36).slice(2, 10);
  return `${prefix}_${rnd}`;
}

const SELECT_CLS =
  "h-9 w-full rounded-sm border border-input bg-surface-2 px-3 text-sm";

function TopologyInner() {
  const [tops, setTops] = React.useState<TopologyItem[]>([]);
  const [current, setCurrent] = React.useState<TopologyDetail | null>(null);
  const [nodes, setNodes, onNodesChange] = useNodesState<TopoFlowNode>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [types, setTypes] = React.useState<TopologyNodeType[]>([]);
  const [iconCandidates, setIconCandidates] = React.useState<string[]>([]);
  const [assets, setAssets] = React.useState<AssetItem[]>([]);
  const [sel, setSel] = React.useState<{ kind: "node" | "edge"; id: string } | null>(null);
  const [dirty, setDirty] = React.useState(false);
  const [msg, setMsg] = React.useState("");
  // 首屏：三份基础数据（拓扑列表 / 节点类型 / 资产）到齐前画骨架
  const [loading, setLoading] = React.useState(true);

  const [name, setName] = React.useState("");
  const [desc, setDesc] = React.useState("");
  const [enabled, setEnabled] = React.useState(true);

  const [assetFilter, setAssetFilter] = React.useState("");
  const [genPicked, setGenPicked] = React.useState<string[]>([]);
  const [newType, setNewType] = React.useState({ name: "", icon: "Box", color: "#64748b" });

  const { screenToFlowPosition } = useReactFlow();
  const wrapRef = React.useRef<HTMLDivElement>(null);

  // ---------- 数据加载 ----------

  async function loadTops() {
    const d = await apiFetch<{ items: TopologyItem[] }>("/api/topologies");
    setTops(d.items);
  }
  async function loadTypes() {
    const d = await apiFetch<NodeTypeList>("/api/topologies/node-types");
    setTypes(d.items);
    setIconCandidates(d.icon_candidates);
  }
  async function loadAssets() {
    const d = await apiFetch<{ items: AssetItem[] }>("/api/assets?limit=500");
    setAssets(d.items);
  }

  React.useEffect(() => {
    Promise.all([loadTops(), loadTypes(), loadAssets()])
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const typeMap = React.useMemo(
    () => Object.fromEntries(types.map((t) => [t.key, t])) as Record<string, TopologyNodeType>,
    [types]
  );
  const assetMap = React.useMemo(
    () => Object.fromEntries(assets.map((a) => [a.id, a])) as Record<string, AssetItem>,
    [assets]
  );

  // 渲染时补上图标/颜色/资产标签（不落库）
  const viewNodes = React.useMemo(
    () =>
      nodes.map((n) => {
        const t = typeMap[n.data.node_type];
        return {
          ...n,
          data: {
            ...n.data,
            icon: t?.icon ?? "Box",
            color: t?.color ?? "#64748b",
            asset_labels: (n.data.asset_ids ?? [])
              .map((id) => assetMap[id]?.ip)
              .filter((x): x is string => Boolean(x)),
          },
        };
      }),
    [nodes, typeMap, assetMap]
  );

  // ---------- 拓扑操作 ----------

  async function openTopology(id: string) {
    const d = await apiFetch<TopologyDetail>(`/api/topologies/${id}`);
    setCurrent(d);
    setName(d.name);
    setDesc(d.description);
    setEnabled(d.enabled);
    setNodes(
      (d.graph.nodes ?? []).map((n) => ({
        id: n.id,
        type: "topoNode",
        position: n.position,
        data: {
          label: n.data.label ?? "",
          node_type: n.data.node_type ?? "",
          asset_ids: n.data.asset_ids ?? [],
          zone: n.data.zone ?? "",
          note: n.data.note ?? "",
        },
      }))
    );
    setEdges(
      (d.graph.edges ?? []).map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.label ?? "",
        type: "smoothstep",
      }))
    );
    setSel(null);
    setDirty(false);
  }

  async function createTopology() {
    const nm = name.trim() || `新拓扑 ${formatDateTime(new Date())}`;
    try {
      const d = await apiFetch<TopologyDetail>("/api/topologies", {
        method: "POST",
        body: JSON.stringify({ name: nm, description: "", graph: { nodes: [], edges: [] } }),
      });
      await loadTops();
      await openTopology(d.id);
      setMsg("已新建拓扑");
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "新建失败");
    }
  }

  async function saveTopology() {
    if (!current) return;
    const payload = {
      name: name.trim() || current.name,
      description: desc,
      enabled,
      graph: {
        nodes: nodes.map((n) => ({
          id: n.id,
          type: "topoNode",
          position: n.position,
          data: n.data,
        })),
        edges: edges.map((e) => ({
          id: e.id,
          source: e.source,
          target: e.target,
          label: String(e.label ?? ""),
        })),
      },
    };
    try {
      const d = await apiFetch<TopologyDetail>(`/api/topologies/${current.id}`, {
        method: "PUT",
        body: JSON.stringify(payload),
      });
      setCurrent(d);
      setDirty(false);
      setMsg("已保存，正在异步向量化…");
      loadTops();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "保存失败");
    }
  }

  async function deleteTopology(id: string) {
    await apiFetch(`/api/topologies/${id}`, { method: "DELETE" });
    if (current?.id === id) {
      setCurrent(null);
      setNodes([]);
      setEdges([]);
    }
    loadTops();
  }

  async function reindexTopology() {
    if (!current) return;
    await apiFetch(`/api/topologies/${current.id}/reindex`, { method: "POST" });
    setMsg("已提交重算");
    loadTops();
  }

  async function toggleEnabled(t: TopologyItem) {
    try {
      const d = await apiFetch<TopologyDetail>(`/api/topologies/${t.id}`);
      await apiFetch(`/api/topologies/${t.id}`, {
        method: "PUT",
        body: JSON.stringify({
          name: d.name,
          description: d.description,
          enabled: !t.enabled,
          graph: d.graph,
        }),
      });
      if (current?.id === t.id) setEnabled(!t.enabled);
      await loadTops();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "更新失败");
    }
  }

  // ---------- 画布交互 ----------

  const onConnect = React.useCallback(
    (c: Connection) => {
      setEdges((es) => addEdge({ ...c, id: uid("e"), label: "", type: "smoothstep" }, es));
      setDirty(true);
    },
    [setEdges]
  );

  function addNodeAt(typeKey: string, pos: { x: number; y: number }) {
    const t = typeMap[typeKey];
    setNodes((ns) => [
      ...ns,
      {
        id: uid("n"),
        type: "topoNode",
        position: { x: Math.round(pos.x / GRID) * GRID, y: Math.round(pos.y / GRID) * GRID },
        data: {
          label: t?.name ?? "新设备",
          node_type: typeKey,
          asset_ids: [],
          zone: "",
          note: "",
        },
      },
    ]);
    setDirty(true);
  }

  function onDrop(e: React.DragEvent) {
    e.preventDefault();
    const typeKey = e.dataTransfer.getData("application/topology-type");
    if (!typeKey) return;
    const pos = screenToFlowPosition({ x: e.clientX, y: e.clientY });
    addNodeAt(typeKey, pos);
  }

  function patchSelectedNode(patch: Partial<TopoNodePayload>) {
    if (sel?.kind !== "node") return;
    setNodes((ns) =>
      ns.map((n) => (n.id === sel.id ? { ...n, data: { ...n.data, ...patch } } : n))
    );
    setDirty(true);
  }

  function patchSelectedEdge(patch: Partial<Edge>) {
    if (sel?.kind !== "edge") return;
    setEdges((es) => es.map((e) => (e.id === sel.id ? { ...e, ...patch } : e)));
    setDirty(true);
  }

  function deleteSelected() {
    if (!sel) return;
    if (sel.kind === "node") {
      setNodes((ns) => ns.filter((n) => n.id !== sel.id));
      setEdges((es) => es.filter((e) => e.source !== sel.id && e.target !== sel.id));
    } else {
      setEdges((es) => es.filter((e) => e.id !== sel.id));
    }
    setSel(null);
    setDirty(true);
  }

  function generateFromAssets() {
    if (genPicked.length === 0) return;
    const startX = 80;
    const startY = 80;
    const perRow = 4;
    const newNodes: TopoFlowNode[] = genPicked.map((aid, i) => {
      const a = assetMap[aid];
      const guessed = guessType(a);
      return {
        id: uid("n"),
        type: "topoNode",
        position: {
          x: startX + (i % perRow) * 220,
          y: startY + Math.floor(i / perRow) * 140,
        },
        data: {
          label: a?.asset_name || a?.hostname || a?.ip || "资产",
          node_type: guessed,
          asset_ids: [aid],
          zone: a?.network_zone ?? "",
          note: "",
        },
      };
    });
    setNodes((ns) => [...ns, ...newNodes]);
    setGenPicked([]);
    setDirty(true);
    setMsg(`已生成 ${newNodes.length} 个节点，记得保存`);
  }

  function guessType(a: AssetItem | undefined): string {
    const hay = `${a?.asset_type ?? ""} ${a?.asset_name ?? ""} ${a?.services ?? ""}`.toLowerCase();
    if (hay.includes("数据库") || hay.includes("db") || hay.includes("mysql")) return "db_server";
    if (hay.includes("web") || hay.includes("应用") || hay.includes("app")) return "app_server";
    if (hay.includes("dns")) return "dns";
    if (hay.includes("防火墙") || hay.includes("fw")) return "firewall";
    if (hay.includes("vpn")) return "vpn";
    if (hay.includes("交换机") || hay.includes("switch")) return "switch";
    if (hay.includes("审计") || hay.includes("日志")) return "log_audit";
    return "endpoint";
  }

  async function createNodeType() {
    if (!newType.name.trim()) return;
    try {
      await apiFetch("/api/topologies/node-types", {
        method: "POST",
        body: JSON.stringify({ ...newType, name: newType.name.trim() }),
      });
      setNewType({ name: "", icon: "Box", color: "#64748b" });
      loadTypes();
    } catch (e) {
      setMsg(e instanceof ApiError ? errorText(e.body) : "新增类型失败");
    }
  }

  const selNode = sel?.kind === "node" ? nodes.find((n) => n.id === sel.id) : undefined;
  const selEdge = sel?.kind === "edge" ? edges.find((e) => e.id === sel.id) : undefined;
  const filteredAssets = assets.filter((a) =>
    assetFilter
      ? `${a.ip} ${a.asset_name} ${a.hostname} ${a.business_system}`
          .toLowerCase()
          .includes(assetFilter.toLowerCase())
      : true
  );

  return (
    <div className="min-h-screen">
      <Nav />
      <main className="ml-56 p-4">
        <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h1 className="text-xl font-medium">
            网络拓扑{current ? ` · ${name}` : ""}
            {dirty && <span className="ml-2 text-xs text-sev-medium-fg">未保存</span>}
          </h1>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" onClick={saveTopology} disabled={!current}>
              保存
            </Button>
            <Button size="sm" variant="outline" onClick={reindexTopology} disabled={!current}>
              重算向量
            </Button>
            <Button size="sm" variant="outline" onClick={deleteSelected} disabled={!sel}>
              删除选中
            </Button>
          </div>
        </div>
        {msg && <p className="text-xs text-primary">{msg}</p>}

        <div className="grid grid-cols-[260px_1fr_300px] gap-3">
          {/* 左栏 */}
          <div className="space-y-3">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle>拓扑图（{tops.length}）</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <Input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="拓扑名称"
                  aria-label="拓扑名称"
                />
                <div className="flex gap-2">
                  <Button size="sm" onClick={createTopology}>
                    新建
                  </Button>
                  <Button size="sm" variant="outline" onClick={saveTopology} disabled={!current}>
                    保存
                  </Button>
                </div>
                <div className="max-h-56 space-y-1 overflow-auto">
                  {loading &&
                    Array.from({ length: 4 }).map((_, i) => (
                      <Skeleton key={i} className="h-10 w-full" />
                    ))}
                  {!loading &&
                    tops.map((t) => (
                    <div
                      key={t.id}
                      className={[
                        "cursor-pointer rounded-sm border px-2 py-1.5 text-xs transition-colors",
                        current?.id === t.id
                          ? "border-primary bg-primary/10"
                          : "border-border-subtle hover:bg-accent",
                      ].join(" ")}
                      onClick={() => openTopology(t.id)}
                    >
                      <div className="flex items-center justify-between gap-1">
                        <span className="truncate font-medium">{t.name}</span>
                        <button
                          className="text-sev-critical-fg"
                          aria-label={`删除拓扑 ${t.name}`}
                          onClick={(e) => {
                            e.stopPropagation();
                            deleteTopology(t.id);
                          }}
                        >
                          删
                        </button>
                      </div>
                      <div className="mt-0.5 flex items-center gap-1 text-muted-foreground">
                        <span className="tabular-nums">
                          {t.node_count} 节点 / {t.edge_count} 连线
                        </span>
                        <Badge
                          variant={
                            t.status === "indexed" ? "low" : t.status === "failed" ? "high" : "info"
                          }
                        >
                          {statusText(t.status)}
                        </Badge>
                        <button
                          className="underline"
                          aria-label={`${t.enabled ? "停用" : "启用"}拓扑 ${t.name}`}
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleEnabled(t);
                          }}
                        >
                          {t.enabled ? "停用" : "启用"}
                        </button>
                      </div>
                    </div>
                  ))}
                  {!loading && tops.length === 0 && (
                    <EmptyState
                      size="compact"
                      title="暂无拓扑"
                      hint="先新建一张，或从下方资产批量生成节点"
                    />
                  )}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle>节点类型（拖到画布）</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="grid grid-cols-2 gap-1">
                  {loading &&
                    Array.from({ length: 6 }).map((_, i) => (
                      <Skeleton key={i} className="h-7 w-full" />
                    ))}
                  {!loading &&
                    types.map((t) => {
                      const Icon = resolveIcon(t.icon);
                      return (
                        <div
                          key={t.key}
                          draggable
                          onDragStart={(e) =>
                            e.dataTransfer.setData("application/topology-type", t.key)
                          }
                          className="flex cursor-grab items-center gap-1.5 rounded-sm border border-border-subtle px-2 py-1.5 text-xs hover:bg-accent"
                          title={t.name}
                        >
                          <Icon size={14} color={t.color} />
                          <span className="truncate">{t.name}</span>
                        </div>
                      );
                    })}
                  {!loading && types.length === 0 && (
                    <EmptyState
                      className="col-span-2"
                      size="compact"
                      title="暂无节点类型"
                      hint="在下方新增一个自定义类型"
                    />
                  )}
                </div>
                <div className="space-y-1 border-t border-border-subtle pt-2">
                  <Input
                    value={newType.name}
                    onChange={(e) => setNewType({ ...newType, name: e.target.value })}
                    placeholder="自定义类型名称"
                    aria-label="自定义节点类型名称"
                    className="h-8 text-xs"
                  />
                  <div className="flex gap-1">
                    <select
                      value={newType.icon}
                      onChange={(e) => setNewType({ ...newType, icon: e.target.value })}
                      aria-label="节点类型图标"
                      className="h-8 flex-1 rounded-sm border border-input bg-surface-2 px-2 text-xs"
                    >
                      {iconCandidates.map((n) => (
                        <option key={n} value={n}>
                          {n}
                        </option>
                      ))}
                    </select>
                    <input
                      type="color"
                      value={newType.color}
                      onChange={(e) => setNewType({ ...newType, color: e.target.value })}
                      aria-label="节点类型颜色"
                      className="h-8 w-10 rounded-sm border border-input bg-surface-2"
                    />
                  </div>
                  <Button size="sm" variant="outline" className="w-full" onClick={createNodeType}>
                    新增类型
                  </Button>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle>从资产批量生成节点</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <Input
                  value={assetFilter}
                  onChange={(e) => setAssetFilter(e.target.value)}
                  placeholder="搜索资产"
                  aria-label="搜索要生成节点的资产"
                  className="h-8 text-xs"
                />
                <div className="max-h-40 space-y-0.5 overflow-auto">
                  {loading &&
                    Array.from({ length: 5 }).map((_, i) => (
                      <Skeleton key={i} className="h-5 w-full" />
                    ))}
                  {!loading &&
                    filteredAssets.slice(0, 100).map((a) => (
                      <label key={a.id} className="flex items-center gap-2 text-xs">
                        <input
                          type="checkbox"
                          checked={genPicked.includes(a.id)}
                          onChange={(e) =>
                            setGenPicked((p) =>
                              e.target.checked ? [...p, a.id] : p.filter((x) => x !== a.id)
                            )
                          }
                        />
                        <span className="font-mono">{a.ip}</span>
                        <span className="truncate text-muted-foreground">
                          {a.asset_name || a.hostname || ""}
                        </span>
                      </label>
                    ))}
                  {!loading && filteredAssets.length === 0 && (
                    <EmptyState size="compact" title="没有匹配的资产" hint="换个关键词，或先去资产页新增" />
                  )}
                </div>
                <Button
                  size="sm"
                  variant="outline"
                  className="w-full"
                  disabled={genPicked.length === 0}
                  onClick={generateFromAssets}
                >
                  生成 {genPicked.length} 个节点
                </Button>
              </CardContent>
            </Card>
          </div>

          {/* 画布 */}
          <div
            ref={wrapRef}
            className="h-[720px] rounded-md border border-border bg-background"
            onDrop={onDrop}
            onDragOver={(e) => e.preventDefault()}
          >
            <ReactFlow
              nodes={viewNodes}
              edges={edges}
              nodeTypes={nodeTypes}
              onNodesChange={(c) => {
                onNodesChange(c);
                if (c.some((x) => x.type === "position" || x.type === "remove")) setDirty(true);
              }}
              onEdgesChange={onEdgesChange}
              onConnect={onConnect}
              onNodeClick={(_, n) => setSel({ kind: "node", id: n.id })}
              onEdgeClick={(_, e) => setSel({ kind: "edge", id: e.id })}
              onPaneClick={() => setSel(null)}
              connectionMode={ConnectionMode.Loose}
              snapToGrid
              snapGrid={[GRID, GRID]}
              fitView
              proOptions={{ hideAttribution: true }}
            >
              <Background gap={GRID} />
              <Controls />
              <MiniMap pannable zoomable />
            </ReactFlow>
          </div>

          {/* 右栏属性 */}
          <div className="space-y-3">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle>属性</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-xs">
                {!sel && (
                  <EmptyState size="compact" title="未选中对象" hint="选中节点或连线后在这里编辑属性" />
                )}

                {selNode && (
                  <>
                    <label className="block text-muted-foreground">设备名</label>
                    <Input
                      value={selNode.data.label}
                      onChange={(e) => patchSelectedNode({ label: e.target.value })}
                      aria-label="设备名"
                      className="h-8 text-xs"
                    />
                    <label className="block text-muted-foreground">类型</label>
                    <select
                      value={selNode.data.node_type}
                      onChange={(e) => patchSelectedNode({ node_type: e.target.value })}
                      aria-label="节点类型"
                      className={`${SELECT_CLS} h-8 text-xs`}
                    >
                      {types.map((t) => (
                        <option key={t.key} value={t.key}>
                          {t.name}
                        </option>
                      ))}
                    </select>
                    <label className="block text-muted-foreground">网络区域</label>
                    <Input
                      value={selNode.data.zone}
                      onChange={(e) => patchSelectedNode({ zone: e.target.value })}
                      aria-label="网络区域"
                      className="h-8 text-xs"
                      placeholder="生产网 / DMZ / 办公网"
                    />
                    <label className="block text-muted-foreground">备注</label>
                    <Input
                      value={selNode.data.note}
                      onChange={(e) => patchSelectedNode({ note: e.target.value })}
                      aria-label="备注"
                      className="h-8 text-xs"
                    />
                    <label className="block text-muted-foreground">
                      关联资产（可多选，当前{" "}
                      <span className="tabular-nums">{selNode.data.asset_ids.length}</span> 个）
                    </label>
                    <div className="max-h-48 space-y-0.5 overflow-auto rounded-xs bg-surface-1 p-1">
                      {filteredAssets.slice(0, 200).map((a) => (
                        <label key={a.id} className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={selNode.data.asset_ids.includes(a.id)}
                            onChange={(e) =>
                              patchSelectedNode({
                                asset_ids: e.target.checked
                                  ? [...selNode.data.asset_ids, a.id]
                                  : selNode.data.asset_ids.filter((x) => x !== a.id),
                              })
                            }
                          />
                          <span className="font-mono">{a.ip}</span>
                          <span className="truncate text-muted-foreground">
                            {a.asset_name || a.hostname || ""}
                          </span>
                        </label>
                      ))}
                      {filteredAssets.length === 0 && (
                        <EmptyState size="compact" title="没有匹配的资产" />
                      )}
                    </div>
                  </>
                )}

                {selEdge && (
                  <>
                    <label className="block text-muted-foreground">连线标签（网段 / VLAN / 链路）</label>
                    <Input
                      value={String(selEdge.label ?? "")}
                      onChange={(e) => patchSelectedEdge({ label: e.target.value })}
                      aria-label="连线标签"
                      className="h-8 text-xs"
                      placeholder="10.100.0.0/24"
                    />
                  </>
                )}
              </CardContent>
            </Card>

            {current && (
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle>拓扑设置</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2 text-xs">
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={enabled}
                      onChange={(e) => {
                        setEnabled(e.target.checked);
                        setDirty(true);
                      }}
                    />
                    参与 RAG 检索
                  </label>
                  <label className="block text-muted-foreground" htmlFor="topo-desc">
                    说明
                  </label>
                  <textarea
                    id="topo-desc"
                    value={desc}
                    onChange={(e) => {
                      setDesc(e.target.value);
                      setDirty(true);
                    }}
                    className="h-20 w-full rounded-sm border border-input bg-surface-2 p-2 text-xs"
                    placeholder="拓扑说明（会一起进入知识库）"
                  />
                  <p className="tabular-nums text-muted-foreground">
                    状态：{statusText(current.status)}
                    {current.indexed_at ? ` · 最近向量化 ${formatDateTime(current.indexed_at)}` : ""}
                  </p>
                  <p className="text-muted-foreground">
                    提示：跳数/节点上限由后端配置（ST_TOPOLOGY_HOPS / ST_TOPOLOGY_MAX_NODES）
                  </p>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
        </div>
      </main>
    </div>
  );
}

export default function TopologyPage() {
  return (
    <ReactFlowProvider>
      <TopologyInner />
    </ReactFlowProvider>
  );
}
