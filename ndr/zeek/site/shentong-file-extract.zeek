## 深瞳 · 明文文件提取（采集批 4）
##
## 目标：把明文协议（HTTP / FTP）传输的文件体落盘，供调查时按 fuid 下载取证。
##
## 本脚本只做一件事：在 file_new 时给该文件挂上 Zeek 的提取分析器。其余交给 Zeek 与入口：
##   - 落盘目录与单文件上限由 base/files/extract 的 FileExtract 决定（见下面的 redef）；
##   - 提取件用 Zeek 文件 id（fuid）命名，于是 files.log 的 extracted 字段 = fuid，
##     磁盘路径 = /extract/<fuid>，后端 GET /api/files/{fuid} 直接按 fuid 拼路径；
##   - **不做 MIME 白名单判定**：Zeek 脚本没有删文件的 BIF，白名单判定与删除由
##     entrypoint.sh 的清理循环（extract_cleanup.py，默认每 5 分钟一次）按 files.log 的
##     mime_type 执行，白名单唯一来源在那个助手里。
##
## 上限说明：default_limit 是单个文件最多提取的字节数，超过则截断（且不再追写），并在
## files.log 里置 extracted_cutoff=T、extracted_size=<实际落盘字节数>；total_bytes 仍是完整大小。

@load base/frameworks/files
@load base/files/extract

module ShentongFileExtract;

export {
	## 提取件落盘目录。必须与 docker-compose 的 zeek-extract 卷挂载点、后端
	## settings.extract_dir 一致，否则下载接口找不到文件。
	redef FileExtract::prefix = "/extract/";

	## 单文件提取上限 16 MiB（超过截断，files.log 记 extracted_cutoff）。
	redef FileExtract::default_limit = 16777216;

	## 参与提取的来源协议。只取明文的 HTTP / FTP：SSL / SMTP 等要么是密文、
	## 要么与调查关注点无关，提取它们只是白占磁盘。
	const sources: set[string] = { "HTTP", "FTP" } &redef;
}

event file_new(f: fa_file)
	{
	if ( ! f?$source || f$source !in sources )
		return;

	Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=f$id]);
	}
