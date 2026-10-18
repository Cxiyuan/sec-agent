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
  EmptyState,
  Section,
  SettingsGrid,
  SettingsMain,
  SettingsRail,
  Stat,
  StatSkeleton,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TableSkeleton,
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
  /** 首次加载：还没读到就先画骨架，别把「正在读」写成「没有配置项」 */
  const [loading, setLoading] = React.useState(true);

  async function load() {
    errs.reset();
    await loadInto(errs, SRC.audit, "/api/config/audit", (d: ConfigAuditPayload) => setData(d));
    setLoading(false);
  }

  React.useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const items = data?.items || [];
  const warnings = data?.warnings || [];
  /** 逐项里有提示的项（warnings 是整段结论，和逐项提示不是一回事，分开计数） */
  const warned = items.filter((it) => !!it.warn).length;
  const okCount = items.length - warned;

  return (
    <PageShell title="配置体检">
      <div className="space-y-4">
        <PanelError errors={errs} />

        <Section
          title="体检结果"
          description="只读检查：每项显示当前生效值与来源；口令/令牌只报已配置与长度。"
          extra={
            <>
              {data?.checked_at ? (
                <span className="text-xs text-muted-foreground">
                  检查于 {formatDateTime(data.checked_at)}
                </span>
              ) : null}
              {data?.default_agent_host ? (
                <Badge variant="outline">智能体地址常量：{data.default_agent_host}</Badge>
              ) : null}
              <Button size="sm" variant="outline" onClick={() => void load()}>
                刷新
              </Button>
            </>
          }
        >
          {loading && !data ? (
            <StatSkeleton count={3} className="md:grid-cols-3" />
          ) : (
            <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
              <Stat label="配置项" value={items.length} size="md" hint="环境 / 数据库 / 编排 / 默认值" />
              <Stat
                label="需要处理"
                value={warnings.length}
                size="md"
                tone={warnings.length ? "medium" : "ok"}
                hint={warnings.length ? "见下方清单" : "没有待处理项"}
              />
              <Stat
                label="逐项正常"
                value={okCount}
                size="md"
                hint={`其余 ${warned} 项带提示`}
              />
            </div>
          )}
        </Section>

        {/* 配置项表在左、待处理清单在右：这一页的动作只有两个 —— 「逐项核对」和
            「把需要处理的改掉」，拆成两列之后右边那列就是待办，左边那列是证据。 */}
        <Section
          title={`配置项（${items.length}）`}
          description="按来源逐项列出当前生效值；右侧是这一轮需要处理的项。"
        >
          <SettingsGrid>
            <SettingsMain>
              <Card>
                <CardContent className="pt-4">
                  {loading && !data ? (
                    <TableSkeleton rows={8} cols={5} />
                  ) : items.length ? (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>项</TableHead>
                          <TableHead className="w-36">来源</TableHead>
                          <TableHead className="w-52">当前生效值</TableHead>
                          <TableHead className="w-20">状态</TableHead>
                          <TableHead>说明 / 提示</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {items.map((it) => (
                          <TableRow key={it.key}>
                            <TableCell className="font-medium text-foreground">{it.name}</TableCell>
                            <TableCell className="text-muted-foreground">{it.source}</TableCell>
                            <TableCell className="font-mono text-xs">
                              {it.value}
                              {it.secret ? (
                                <Badge variant="outline" className="ml-1">
                                  已脱敏
                                </Badge>
                              ) : null}
                            </TableCell>
                            <TableCell>
                              {it.warn ? (
                                <Badge variant="medium">需处理</Badge>
                              ) : (
                                <Badge variant="success">正常</Badge>
                              )}
                            </TableCell>
                            <TableCell className="text-muted-foreground">
                              {it.warn ? <span className="text-sev-medium-fg">{it.warn}</span> : null}
                              {it.warn && it.note ? "；" : ""}
                              {it.note || ""}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  ) : (
                    <EmptyState
                      title={errs.isFailed(SRC.audit) || data?.error ? "配置项读取失败" : "没有配置项数据"}
                      hint={
                        errs.isFailed(SRC.audit)
                          ? "见上方错误条：后端异常或网络不通，不能当成「没有配置」"
                          : data?.error || "体检接口没有返回任何配置项"
                      }
                      tone={errs.isFailed(SRC.audit) || data?.error ? "danger" : "muted"}
                      action={
                        <Button size="sm" variant="outline" onClick={() => void load()}>
                          重新读取
                        </Button>
                      }
                    />
                  )}
                  {data?.note ? (
                    <p className="mt-3 text-xs leading-relaxed text-muted-foreground">{data.note}</p>
                  ) : null}
                </CardContent>
              </Card>
            </SettingsMain>

            <SettingsRail>
              {loading && !data ? (
                <Card>
                  <CardContent className="space-y-2 pt-4">
                    <Skeleton className="h-3.5 w-20" />
                    <Skeleton className="h-3 w-full" />
                    <Skeleton className="h-3 w-4/5" />
                  </CardContent>
                </Card>
              ) : warnings.length ? (
                /* 需要处理：有问题用语义色标出；没有问题也明确说「正常」，不要整块消失 */
                <Card className="border-sev-medium-bd bg-sev-medium-bg">
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-center gap-2 text-sev-medium-fg">
                      需要处理
                      <Badge variant="medium" className="tabular-nums">
                        {warnings.length} 项
                      </Badge>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ul className="list-disc space-y-1 pl-4 text-xs leading-relaxed text-sev-medium-fg">
                      {warnings.map((w, i) => (
                        <li key={i}>{w}</li>
                      ))}
                    </ul>
                  </CardContent>
                </Card>
              ) : data && !data.error && !errs.has ? (
                <Card className="border-sev-ok-bd bg-sev-ok-bg">
                  <CardContent className="flex flex-wrap items-center gap-2 p-3 text-xs text-sev-ok-fg">
                    <Badge variant="success">正常</Badge>
                    本轮检查没有需要处理的配置项。
                  </CardContent>
                </Card>
              ) : null}
            </SettingsRail>
          </SettingsGrid>
        </Section>
      </div>
    </PageShell>
  );
}
