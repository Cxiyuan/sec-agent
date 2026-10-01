"use client";

import { PageShell } from "@/components/page-shell";
import { EsPanel } from "@/components/es-panel";
import { LogstashPanel } from "@/components/logstash-panel";

/** 数据存储：Elasticsearch 连接与索引模板 + Logstash 入库管道。 */
export default function StoragePage() {
  return (
    <PageShell
      title="数据存储"
      desc="归一化后的数据落到哪：Elasticsearch 的地址与事件索引模板，以及 Logstash 的入库管道状态。"
    >
      <EsPanel />
      <LogstashPanel />
    </PageShell>
  );
}
