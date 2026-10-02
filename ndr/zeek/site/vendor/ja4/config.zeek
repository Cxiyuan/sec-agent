## 深瞳自建的最小配置（本文件不是上游文件）
##
## 上游 zeek/config.zeek 除下面两项外，还声明了 JA4S/JA4H/JA4L/JA4SSH/JA4T/JA4X/JA4D 的开关
## （那些属于 FoxIO License 1.1，本项目未收录对应脚本），这里只保留 JA4 本体需要的两项，
## 免得在仓库里出现用不上的 FoxIO 授权开关。
##
##   delimiter —— 指纹各段之间的分隔符，JA4 规定是 "_"
##   JA4_raw   —— 除 ja4 外是否再记原始/排序后的中间形态（默认关，开了 ssl.log 会多 3 列）

module FINGERPRINT;

export {
  option delimiter: string = "_";
  option JA4_raw: bool = F;
}
