# Count, per TLS connection, the application-data records (content type 23)
# each side sent. Only counts and lengths, never contents (they are encrypted).
# Used by mitm_sessions.py: a client that sends application data after a
# handshake with a forged certificate went on using that connection.
@load base/protocols/ssl

# keep the analyzer after the handshake, or no records are seen
redef SSL::disable_analyzer_after_detection = F;

module TLSRec;

export {
	redef enum Log::ID += { LOG };
	type Info: record {
		uid: string &log;
		client_records: count &log &default=0;
		client_bytes: count &log &default=0;
		server_records: count &log &default=0;
		server_bytes: count &log &default=0;
	};
}

global recs: table[string] of Info;

event zeek_init()
	{
	Log::create_stream(TLSRec::LOG, [$columns=Info, $path="tls_records"]);
	}

event ssl_encrypted_data(c: connection, is_client: bool, record_version: count, content_type: count, length: count)
	{
	if ( content_type != 23 )
		return;
	if ( c$uid !in recs )
		recs[c$uid] = Info($uid=c$uid);
	local r = recs[c$uid];
	if ( is_client )
		{ ++r$client_records; r$client_bytes += length; }
	else
		{ ++r$server_records; r$server_bytes += length; }
	}

event connection_state_remove(c: connection)
	{
	if ( c$uid in recs )
		{
		Log::write(TLSRec::LOG, recs[c$uid]);
		delete recs[c$uid];
		}
	}
