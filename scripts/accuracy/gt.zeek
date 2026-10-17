# Ground truth for the miss measurement (accuracy step 1), built with Zeek
# independently of Quarant. Zeek finds TLS, HTTP and MQTT by content (DPD),
# so the port does not matter. One row per TLS session, HTTP request or MQTT
# CONNECT goes to gt.log. Only names are logged, never values: header names,
# URL parameter names, body key names, the Authorization scheme, and whether
# a username or password was present.
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/mqtt
@load base/protocols/ftp
@load base/files/hash

module GT;

export {
	redef enum Log::ID += { LOG };
	type Info: record {
		ts: time &log;
		uid: string &log;
		kind: string &log;
		orig_mac: string &log &optional;
		resp_mac: string &log &optional;
		orig_h: addr &log;
		orig_p: port &log;
		resp_h: addr &log;
		resp_p: port &log;
		# TLS
		version: string &log &optional;
		cipher: string &log &optional;
		client_versions: string &log &optional;
		sni: string &log &optional;
		# HTTP
		method: string &log &optional;
		host: string &log &optional;
		status: count &log &optional;
		req_headers: set[string] &log &optional;
		auth_scheme: string &log &optional;
		uri_params: set[string] &log &optional;
		req_body_keys: set[string] &log &optional;
		resp_body_keys: set[string] &log &optional;
		resp_headers: set[string] &log &optional;
		orig_mime: vector of string &log &optional;
		req_body_len: count &log &optional;
		# MQTT / FTP
		has_username: bool &log &optional;
		has_password: bool &log &optional;
	};
}

# Names that suggest a secret; only names that match are kept for bodies.
const secret_name = /[pP][aA][sS][sS]|[pP][wW][dD]|[tT][oO][kK][eE][nN]|[sS][eE][cC][rR][eE][tT]|[aA][pP][iI]_?[kK][eE][yY]|[aA][uU][tT][hH]|[sS][eE][sS][sS][iI][oO][nN]|^[sS][iI][dD]$|[sS][iI][gG][nN]/;
const key_pat = /[\"']?[A-Za-z0-9_\-\.]{1,40}[\"']?[ \t]*[:=]/;

redef record HTTP::Info += {
	gt_req_headers: set[string] &default=set();
	gt_resp_headers: set[string] &default=set();
	gt_auth: string &optional;
	gt_params: set[string] &default=set();
	gt_req_keys: set[string] &default=set();
	gt_resp_keys: set[string] &default=set();
	gt_req_seen: count &default=0;
	gt_resp_seen: count &default=0;
	gt_orig_mac: string &optional;
	gt_resp_mac: string &optional;
};

redef record SSL::Info += {
	gt_client_versions: string &optional;
	gt_orig_mac: string &optional;
	gt_resp_mac: string &optional;
};

redef record connection += {
	gt_ftp_user: bool &default=F;
	gt_ftp_pass: bool &default=F;
};

event zeek_init()
	{
	Log::create_stream(GT::LOG, [$columns=Info, $path="gt"]);
	Log::remove_default_filter(HTTP::LOG);
	Log::remove_default_filter(SSL::LOG);
	Log::remove_default_filter(MQTT::CONNECT_LOG);
	Log::remove_default_filter(FTP::LOG);
	Log::remove_default_filter(Conn::LOG);
	Log::remove_default_filter(Files::LOG);
	}

function base(c: connection, kind: string): Info
	{
	local r = Info($ts=network_time(), $uid=c$uid, $kind=kind,
	               $orig_h=c$id$orig_h, $orig_p=c$id$orig_p,
	               $resp_h=c$id$resp_h, $resp_p=c$id$resp_p);
	if ( c$orig?$l2_addr ) r$orig_mac = c$orig$l2_addr;
	if ( c$resp?$l2_addr ) r$resp_mac = c$resp$l2_addr;
	return r;
	}

# The log events can fire after the connection is gone (lookup_connection
# then fails), so the MACs are copied into the protocol records early.
function from_rec(id: conn_id, uid: string, ts: time, kind: string, om: string, rm: string): Info
	{
	local r = Info($ts=ts, $uid=uid, $kind=kind, $orig_h=id$orig_h, $orig_p=id$orig_p,
	               $resp_h=id$resp_h, $resp_p=id$resp_p);
	if ( om != "" ) r$orig_mac = om;
	if ( rm != "" ) r$resp_mac = rm;
	return r;
	}

function body_keys(data: string, out: set[string])
	{
	for ( m in find_all(data, key_pat) )
		{
		local k = gsub(m, /[\"' \t:=]/, "");
		if ( secret_name in k )
			add out[to_lower(k)];
		}
	}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &priority=3
	{
	if ( ! c?$http ) return;
	if ( c$orig?$l2_addr ) c$http$gt_orig_mac = c$orig$l2_addr;
	if ( c$resp?$l2_addr ) c$http$gt_resp_mac = c$resp$l2_addr;
	# The unescaped URI, so that an encoded query (%26, %3d) is split into
	# its keys too and no value ends up in a key name.
	local q = find_last(unescaped_URI, /\?.*/);
	if ( q == "" ) return;
	for ( _, kv in split_string(sub(q, /^\?/, ""), /&/) )
		{
		local k = split_string1(kv, /=/)[0];
		if ( k != "" && |k| <= 40 )
			add c$http$gt_params[to_lower(k)];
		}
	}

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string) &priority=3
	{
	if ( ! c?$http ) return;
	if ( is_orig )
		{
		add c$http$gt_req_headers[to_lower(name)];
		if ( name == "AUTHORIZATION" )
			c$http$gt_auth = split_string1(value, / /)[0];
		}
	else
		add c$http$gt_resp_headers[to_lower(name)];
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) &priority=3
	{
	if ( ! c?$http ) return;
	if ( is_orig && c$http$gt_req_seen < 8192 )
		{
		c$http$gt_req_seen += length;
		body_keys(data, c$http$gt_req_keys);
		}
	else if ( ! is_orig && c$http$gt_resp_seen < 8192 )
		{
		c$http$gt_resp_seen += length;
		body_keys(data, c$http$gt_resp_keys);
		}
	}

event HTTP::log_http(rec: HTTP::Info)
	{
	local r = from_rec(rec$id, rec$uid, rec$ts, "http", rec?$gt_orig_mac ? rec$gt_orig_mac : "", rec?$gt_resp_mac ? rec$gt_resp_mac : "");
	if ( rec?$method ) r$method = rec$method;
	if ( rec?$host ) r$host = rec$host;
	if ( rec?$status_code ) r$status = rec$status_code;
	r$req_headers = rec$gt_req_headers;
	r$resp_headers = rec$gt_resp_headers;
	if ( rec?$gt_auth ) r$auth_scheme = rec$gt_auth;
	r$uri_params = rec$gt_params;
	r$req_body_keys = rec$gt_req_keys;
	r$resp_body_keys = rec$gt_resp_keys;
	if ( rec?$orig_mime_types ) r$orig_mime = rec$orig_mime_types;
	r$req_body_len = rec$request_body_len;
	Log::write(GT::LOG, r);
	}

function set_macs(c: connection)
	{
	if ( c$orig?$l2_addr ) c$ssl$gt_orig_mac = c$orig$l2_addr;
	if ( c$resp?$l2_addr ) c$ssl$gt_resp_mac = c$resp$l2_addr;
	}

event ssl_extension_supported_versions(c: connection, is_client: bool, versions: index_vec)
	{
	if ( ! is_client || ! c?$ssl ) return;
	local names: vector of string = vector();
	for ( _, v in versions )
		names += SSL::version_strings[v];
	c$ssl$gt_client_versions = join_string_vec(names, ",");
	}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=3
	{
	if ( ! c?$ssl ) return;
	if ( ! c$ssl?$gt_client_versions )
		c$ssl$gt_client_versions = "max=" + SSL::version_strings[version];
	set_macs(c);
	}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) &priority=3
	{
	if ( c?$ssl ) set_macs(c);
	}

event SSL::log_ssl(rec: SSL::Info)
	{
	local r = from_rec(rec$id, rec$uid, rec$ts, "tls", rec?$gt_orig_mac ? rec$gt_orig_mac : "", rec?$gt_resp_mac ? rec$gt_resp_mac : "");
	if ( rec?$version ) r$version = rec$version;
	if ( rec?$cipher ) r$cipher = rec$cipher;
	if ( rec?$gt_client_versions ) r$client_versions = rec$gt_client_versions;
	if ( rec?$server_name ) r$sni = rec$server_name;
	Log::write(GT::LOG, r);
	}

event mqtt_connect(c: connection, msg: MQTT::ConnectMsg)
	{
	local r = base(c, "mqtt");
	r$has_username = msg?$username;
	r$has_password = msg?$password;
	Log::write(GT::LOG, r);
	}

event ftp_request(c: connection, command: string, arg: string)
	{
	if ( command == "USER" && ! c$gt_ftp_user )
		{
		c$gt_ftp_user = T;
		local r = base(c, "ftp");
		r$has_username = T; r$has_password = F;
		Log::write(GT::LOG, r);
		}
	if ( command == "PASS" && ! c$gt_ftp_pass )
		{
		c$gt_ftp_pass = T;
		local p = base(c, "ftp");
		p$has_username = F; p$has_password = T;
		Log::write(GT::LOG, p);
		}
	}
