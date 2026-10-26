"use client";

import { PageShell } from "@/components/page-shell";
import { ExclusionsPanel } from "@/components/exclusions-panel";
import { IngestFiltersPanel } from "@/components/ingest-filters-panel";

/** 过滤规则：降噪（不送检测器但仍入库）与排除（整条丢弃）。 */
export default function FiltersPage() {
  return (
    <PageShell
      title="过滤规则"
      width="wide"
      desc="把噪音挡在分析之前：降噪命中只丢弃「送检测器」这一步（数据仍进 Elasticsearch），排除命中则整条不采集。"
    >
      <IngestFiltersPanel />
      <ExclusionsPanel />
    </PageShell>
  );
}
