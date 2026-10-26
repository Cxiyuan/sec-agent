"use client";

import { PageShell } from "@/components/page-shell";
import { EsPanel } from "@/components/es-panel";
import { LogstashPanel } from "@/components/logstash-panel";

/**
 * 数据存储：Elasticsearch 接入状态与索引模板 + Logstash 入库管道。
 *
 * ES 随系统内置部署，连接信息由部署环境固定，这里没有连接配置项。
 */
export default function StoragePage() {
  return (
    <PageShell
      title="数据存储"
      width="standard"
      desc="归一化后的数据落到哪：Elasticsearch 接入状态与事件索引模板（连接信息由部署环境固定），以及 Logstash 的入库管道状态。"
    >
      <EsPanel />
      <LogstashPanel />
    </PageShell>
  );
}
