## 批 4 单测：明文文件提取脚本（编译期契约）。
##
## 依赖 run.sh 把整棵 site/ 树复制到工作目录并把本文件放到同目录。
## 这里只验证「脚本加载成功 + 常量对得上」；真实的落盘、MIME 白名单与淘汰由
## 服务器探针覆盖（见 docs/ndr-redesign.md 第 12 期）。

@load ./shentong-file-extract

global fails: count = 0;

function check(tag: string, ok: bool) {
    if ( ok ) print fmt("PASS %s", tag);
    else { print fmt("FAIL %s", tag); fails += 1; }
}

event zeek_done() {
    # 落盘目录与单文件上限（与后端 settings.extract_dir / docs 里的口径一致）
    check("extract prefix is /extract/", FileExtract::prefix == "/extract/");
    check("single file limit is 16 MiB", FileExtract::default_limit == 16777216);

    # 只提取明文来源
    check("HTTP is an extraction source", "HTTP" in ShentongFileExtract::sources);
    check("FTP is an extraction source", "FTP" in ShentongFileExtract::sources);
    check("SSL is not an extraction source", "SSL" !in ShentongFileExtract::sources);

    # 提取件名字段是文件框架提供的（files.log 的 extracted / extracted_cutoff / extracted_size）
    local info: Files::Info;
    info$extracted = "Fx00000000000000000";
    info$extracted_size = 1024;
    info$extracted_cutoff = T;
    check("files.log has extracted field", info$extracted == "Fx00000000000000000");
    check("files.log has extracted_size field", info$extracted_size == 1024);
    check("files.log has extracted_cutoff field", info$extracted_cutoff == T);

    print fmt("FAILS=%d", fails);
}
