

redef udp_content_deliver_all_orig = T;
redef udp_content_deliver_all_resp = T;

event udp_contents(u: connection, is_orig: bool, contents: string)
	{
	local fname: string;

	if ( is_orig )
		fname = fmt("udp-contents.orig.%.6f.dat", network_time());
	else
		fname = fmt("udp-contents.resp.%.6f.dat", network_time());

	local out = open(fname);
	enable_raw_output(out);
	print out, contents;
	close(out);
	}
