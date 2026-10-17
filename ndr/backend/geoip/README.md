# 离线地理库（可视化流量 → 访问地域 TOP5）

本目录放**离线地理库**（MaxMind 格式的 `.mmdb`，gz 压缩后随镜像一起发布）。
代码入口：`app/geoip.py`；启用方式：环境变量 `ST_GEOIP_DB` 指向库文件
（镜像构建时已自动 `ENV ST_GEOIP_DB=/app/geoip/ip.mmdb`，开箱可用）。

## 当前数据源

**DB-IP City Lite**（`dbip-city-lite-2026-10.mmdb.gz`）

- 来源：<https://db-ip.com/db/download/ip-to-city-lite>
- 许可：**CC BY 4.0** —— 允许随产品分发，但**必须保留归属**：
  > IP Geolocation by DB-IP (<https://db-ip.com>)
- 覆盖粒度：国家 / 省（一级行政区）/ 城市；精度低于商业库，够"地区 TOP5"用。

### 为什么不用 MaxMind GeoLite2

GeoLite2 下载需要 MaxMind 账号 + License Key（不能无凭据自动获取），
且许可对"随产品再分发"有额外约束。DB-IP Lite 可直接下载、许可清晰、格式同为 mmdb，
`geoip2` 读法完全一致（`reader.city()` / `reader.country()`）。

## 更新方法（每月一次，DB-IP 按月发布）

```bash
# 在本机执行（需要能访问外网），把 YYYY-MM 换成当月
curl -fL -o ndr/backend/geoip/dbip-city-lite-$(date -u +%Y-%m).mmdb.gz \
  "https://download.db-ip.com/free/dbip-city-lite-$(date -u +%Y-%m).mmdb.gz"
rm -f ndr/backend/geoip/dbip-city-lite-*.mmdb.gz.bak
```

然后提交、走 CI 构建镜像即可。**旧的 .gz 可以删掉**（Dockerfile 里用的是 `*.mmdb.gz` 通配，
只解压第一个；保留多份只会让仓库变大）。

## 许可合规

- 本库按 **CC BY 4.0** 分发；界面上「访问地域」属于使用该库产出的结果，
  对外文档/交付材料里请保留上面的归属声明。
- 产品**绝不联网查询**地理信息：只读本地库，访问地址不会发给任何第三方。
