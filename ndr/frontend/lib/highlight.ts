/**
 * 搜索命中高亮。
 *
 * 两个必须守住的点：
 * 1. **必须 escapeRegExp**：运维会搜 `dns (txt)`、`10.0.0.*` 这类带正则元字符的串，
 *    不转义会抛 `SyntaxError` 让整页崩掉 —— 这不是边界情况，DNS 查询名里带括号很常见。
 * 2. **必须产出 ReactNode 而不是 HTML 串**：规则名 / 描述来自后端，是外部数据，
 *    用 `dangerouslySetInnerHTML` 拼接等于给后端开一个 XSS 口子。
 */

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * 把 text 按 needle 切成片段数组；命中片段由调用方包一层 `<mark>`。
 * needle 为空时直接返回 `[text]`（不进正则，省一次编译）。
 */
export function highlightParts(
  text: string,
  needle: string,
): Array<{ s: string; hit: boolean }> {
  if (!needle || !text) return [{ s: text, hit: false }];
  const out: Array<{ s: string; hit: boolean }> = [];
  const re = new RegExp(escapeRegExp(needle), "gi");
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push({ s: text.slice(last, m.index), hit: false });
    out.push({ s: m[0], hit: true });
    last = m.index + m[0].length;
    // 兜底：避免空匹配永不前进（needle 本身是空串时上面已返回，这里防的是 lastIndex 卡住）
    if (m[0].length === 0) re.lastIndex++;
  }
  if (last < text.length) out.push({ s: text.slice(last), hit: false });
  return out;
}
