"use client";

import * as React from "react";
import { PageShell } from "@/components/page-shell";
import { PanelError, loadInto, usePanelErrors } from "@/components/panel-error";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  formatDateTime,
} from "@shentong/ui";
import type { ConfigAuditPayload } from "@/lib/api";

const SRC = { audit: "配置体检（/api/config/audit）" } as const;

/**
 * 配置体检：逐项显示**当前生效值**与**它从哪来**（环境 / 数据库 / 编排部署侧 / 代码默认值）。
 *
 * 为什么有这个页（2026-10 实机教训）：配置分散在三处 —— ①引导项（连库之前就要有，只能来自环境
 * 或部署脚本）、②运行期配置（入库、界面可改）、③编排项（容器还不存在时就要定）。排查时最耗时
 * 的一句是「文件里也有、库里也有，到底哪个生效？」，这个页把答案直接列出来。
 * 口令/令牌/密钥一律脱敏（只报已配置与长度），本页**只读**。
 */
export default function ConfigAuditPage() {
  const errs = usePanelErrors();
  const [data, setData] = React.useState<ConfigAuditPayload | null>(null);

  async function load() {
    errs.reset();
    await loadInto(errs, SRC.audit, "/api/config/audit", (d: ConfigAuditPayload) => setData(d));
  }

  React.useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <PageShell title="配置体检">
      <div className="mb-3">
        <PanelError errors={errs} />
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Button size="sm" variant="outline" onClick={() => void load()}>
          刷新
        </Button>
        {data?.checked_at ? (
          <span className="text-xs text-muted-foreground">
            检查于 {formatDateTime(data.checked_at)}
          </span>
        ) : null}
        {data?.default_agent_host ? (
          <Badge variant="outline">智能体地址常量：{data.default_agent_host}</Badge>
        ) : null}
      </div>

      {data?.warnings?.length ? (
        <Card className="mb-4 border-sev-medium-bd bg-sev-medium-bg">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-sev-medium-fg">需要处理（{data.warnings.length}）</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="list-disc space-y-1 pl-5 text-xs">
              {data.warnings.map((w, i) => (
                <li key={i}>{w}</li>
              ))}
            </ul>
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">配置项（{data?.items?.length ?? 0}）</CardTitle>
        </CardHeader>
        <CardContent>
          {data?.items?.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>项</TableHead>
                  <TableHead>来源</TableHead>
                  <TableHead>当前生效值</TableHead>
                  <TableHead>说明 / 提示</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((it) => (
                  <TableRow key={it.key}>
                    <TableCell className="text-xs font-medium">{it.name}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{it.source}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {it.value}
                      {it.secret ? (
                        <Badge variant="outline" className="ml-1">
                          已脱敏
                        </Badge>
                      ) : null}
                    </TableCell>
                    <TableCell className="text-xs">
                      {it.warn ? <span className="text-sev-medium-fg">{it.warn}</span> : null}
                      {it.warn && it.note ? "；" : ""}
                      <span className="text-muted-foreground">{it.note || ""}</span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-xs text-muted-foreground">
              {data?.error ? `读取失败：${data.error}` : "正在读取…"}
            </p>
          )}
          {data?.note ? (
            <p className="mt-3 text-xs text-muted-foreground">{data.note}</p>
          ) : null}
        </CardContent>
      </Card>
    </PageShell>
  );
}
