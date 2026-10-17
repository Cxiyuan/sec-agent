import type { Config } from "tailwindcss";

/**
 * 「钢蓝仪表台」token 映射。
 *
 * 原则：业务代码只允许用**语义类名**（bg-surface-1 / text-sev-critical-fg / shadow-1），
 * 不再出现 #0ea5e9、bg-red-950 这类硬编码色值。改主题只改 globals.css 的变量。
 *
 * 旧键（muted / secondary / accent / card / destructive）全部保留：
 * 存量组件还在用，删掉会整片报错。
 */
const config: Config = {
  darkMode: ["class"],
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
    "../../packages/ui/src/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        border: "hsl(var(--border))",
        "border-subtle": "hsl(var(--border-subtle))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",

        /* 表面分层 */
        canvas: "hsl(var(--canvas))",
        surface: {
          1: "hsl(var(--surface-1))",
          2: "hsl(var(--surface-2))",
          3: "hsl(var(--surface-3))",
        },

        /* 品牌 */
        brand: {
          50: "hsl(var(--brand-50))",
          500: "hsl(var(--brand-500))",
          600: "hsl(var(--brand-600))",
          700: "hsl(var(--brand-700))",
        },

        /* 严重度：bg / fg / bd 三件套 */
        sev: {
          critical: {
            bg: "hsl(var(--sev-critical-bg))",
            fg: "hsl(var(--sev-critical-fg))",
            bd: "hsl(var(--sev-critical-bd))",
          },
          high: {
            bg: "hsl(var(--sev-high-bg))",
            fg: "hsl(var(--sev-high-fg))",
            bd: "hsl(var(--sev-high-bd))",
          },
          medium: {
            bg: "hsl(var(--sev-medium-bg))",
            fg: "hsl(var(--sev-medium-fg))",
            bd: "hsl(var(--sev-medium-bd))",
          },
          low: {
            bg: "hsl(var(--sev-low-bg))",
            fg: "hsl(var(--sev-low-fg))",
            bd: "hsl(var(--sev-low-bd))",
          },
          info: {
            bg: "hsl(var(--sev-info-bg))",
            fg: "hsl(var(--sev-info-fg))",
            bd: "hsl(var(--sev-info-bd))",
          },
          ok: {
            bg: "hsl(var(--sev-ok-bg))",
            fg: "hsl(var(--sev-ok-fg))",
            bd: "hsl(var(--sev-ok-bd))",
          },
        },

        /* 图表 */
        chart: {
          1: "hsl(var(--chart-1))",
          2: "hsl(var(--chart-2))",
          3: "hsl(var(--chart-3))",
          4: "hsl(var(--chart-4))",
          5: "hsl(var(--chart-5))",
          6: "hsl(var(--chart-6))",
          7: "hsl(var(--chart-7))",
          8: "hsl(var(--chart-8))",
          grid: "hsl(var(--chart-grid))",
          axis: "hsl(var(--chart-axis))",
          track: "hsl(var(--chart-track))",
        },

        /* 旧键保留 */
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
      },
      fontFamily: {
        sans: ["var(--font-sans)"],
        mono: ["var(--font-mono)"],
      },
      fontSize: {
        /* 正文档 13px：12px 偏小、14px 太松，13px 是密集表格的可读与密度的平衡点 */
        13: ["13px", { lineHeight: "20px" }],
        /* KPI 数值档：数字要压得住版面，但不能靠 700 粗体（中文会发糊） */
        28: ["28px", { lineHeight: "34px", letterSpacing: "-0.01em" }],
      },
      borderRadius: {
        xs: "3px",
        sm: "4px",
        md: "6px",
        lg: "8px",
        xl: "12px",
      },
      boxShadow: {
        /* 显式 elevation：1 静止卡片 / 2 hover / 3 浮层 */
        1: "var(--elev-1)",
        2: "var(--elev-2)",
        3: "var(--elev-3)",
        /* 把默认档位也接过来，存量 shadow-sm / shadow-lg 自动跟随新材质 */
        DEFAULT: "var(--elev-1)",
        sm: "var(--elev-1)",
        md: "var(--elev-2)",
        lg: "var(--elev-3)",
      },
    },
  },
  plugins: [],
};

export default config;
