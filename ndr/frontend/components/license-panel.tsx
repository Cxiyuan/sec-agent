"use client";

import * as React from "react";
import { Badge, Button, SettingsBlock, SettingsBoard } from "@shentong/ui";
import type { SystemLicense } from "@/lib/api";
import { PanelError, loadInto, usePanelErrors } from "@/components/panel-error";

const SRC = { license: "系统授权（/api/system/license）" } as const;

/**
 * 系统授权：本机**授权ID**（项目组织身份）。
 *
 * 为什么要这一页：智能体按"项目组织"隔离数据，而一个项目对应的就是一台 NDR。
 * 两边靠这个 8 位 ID 对上号 —— 以前只能靠人工约定一个名字，填错了两边都察觉不到。
 *
 * 它是身份不是密钥：可以展示、抄写；鉴权仍靠 MCP 令牌与门铃推送令牌。
 */
export function LicensePanel() {
  const [info, setInfo] = React.useState<SystemLicense | null>(null);
  const [copied, setCopied] = React.useState(false);
  const errs = usePanelErrors();

  React.useEffect(() => {
    void loadInto(errs, SRC.license, "/api/system/license", setInfo);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  async function copy() {
    if (!info) return;
    try {
      await navigator.clipboard.writeText(info.auth_id);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      // 剪贴板不可用（非安全上下文/权限被拒）时退回选中文本
      const range = document.createRange();
      const node = document.getElementById("auth-id-value");
      if (node) {
        range.selectNodeContents(node);
        const sel = window.getSelection();
        sel?.removeAllRanges();
        sel?.addRange(range);
      }
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <PanelError errors={errs} />
      <SettingsBoard>
        <SettingsBlock
          title="本机授权ID"
          description="由本机硬件机器码派生，用于在智能体侧把「项目组织」绑定到这台 NDR。"
        >
          {info ? (
            <div className="flex flex-col gap-4">
              <div className="flex flex-wrap items-center gap-3">
                <span
                  id="auth-id-value"
                  className="select-all rounded-xs border border-border bg-surface-1 px-4 py-2 font-mono text-3xl font-semibold tracking-[0.25em] text-foreground"
                >
                  {info.auth_id}
                </span>
                <Button size="sm" variant="outline" onClick={() => void copy()}>
                  {copied ? "已复制" : "复制"}
                </Button>
              </div>
              <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                <span>派生来源：{info.source_label}</span>
                {info.stable ? (
                  <Badge variant="outline">硬件绑定</Badge>
                ) : (
                  <Badge variant="medium">不稳定（主机名兜底）</Badge>
                )}
              </div>
              {!info.stable ? (
                <p className="text-xs text-warning">
                  当前读不到硬件 UUID / 系统安装标识，只能退回主机名 —— 换主机名这个 ID 就会变。
                  请检查容器的 <code className="font-mono">/sys/class/dmi/id/product_uuid</code> 是否可读。
                </p>
              ) : null}
            </div>
          ) : (
            <div className="h-10 w-56 animate-pulse rounded-xs bg-surface-2" />
          )}
        </SettingsBlock>

        <SettingsBlock title="怎么用" description="在智能体控制台里录入这个 ID，把项目与 NDR 绑起来。">
          <ol className="list-decimal space-y-2 pl-5 text-sm text-muted-foreground">
            <li>
              打开智能体控制台 → <b className="text-foreground">配置 → 项目组织</b>，新增一个项目。
            </li>
            <li>
              把上面的 <b className="text-foreground">授权ID</b> 原样填入项目的「授权ID」字段，
              同时填这台 NDR 的 MCP 地址与令牌。
            </li>
            <li>
              保存时智能体会调本 NDR 的 <code className="font-mono">server_info</code> 核对 ID；
              不一致或连不上，这个项目会**停掉分析并报警**，不会把数据写到归属不明的库里。
            </li>
            <li>
              换机后本机 ID 会变：到智能体侧把项目的授权ID 改成新的即可恢复（数据仍归该项目）。
            </li>
          </ol>
          <p className="mt-3 text-xs text-muted-foreground">
            这个 ID 只是身份标识，不是密钥 —— 把 MCP 令牌/推送令牌管好才是安全边界。
          </p>
        </SettingsBlock>
      </SettingsBoard>
    </div>
  );
}
