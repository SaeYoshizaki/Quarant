package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"quarant/analyzer"
)

func TestRunZeekImportWritesFlowsAndObservations(t *testing.T) {
	dir := t.TempDir()
	connPath := filepath.Join(dir, "conn.log")
	dnsPath := filepath.Join(dir, "dns.log")
	httpPath := filepath.Join(dir, "http.log")
	tlsPath := filepath.Join(dir, "ssl.log")
	outDir := filepath.Join(dir, "out")

	writeTestFile(t, connPath, "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\n1790409600.000000\tC1\t192.168.8.42\t50000\t198.51.100.10\t443\ttcp\tssl\t120\t500\t2\t3\n")
	writeTestFile(t, dnsPath, "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tquery\n1790409601.000000\tD1\t192.168.8.42\t53000\t8.8.8.8\t53\tapi.camera.example\n")
	writeTestFile(t, httpPath, "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tmethod\thost\turi\n1790409602.000000\tH1\t192.168.8.42\t50001\t198.51.100.11\t80\tGET\tcamera-cloud.example\t/ping\n")
	writeTestFile(t, tlsPath, "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tserver_name\n1790409603.000000\tS1\t192.168.8.42\t50002\t198.51.100.12\t443\ttls.camera.example\n")

	var out bytes.Buffer
	err := runZeekImportCLI([]string{
		"--conn", connPath,
		"--dns", dnsPath,
		"--http", httpPath,
		"--ssl", tlsPath,
		"--out-dir", outDir,
	}, &out)
	if err != nil {
		t.Fatalf("runZeekImportCLI: %v", err)
	}
	flows := readJSONLLines[analyzer.FlowRecord](t, filepath.Join(outDir, "flows.jsonl"))
	if len(flows) != 3 {
		t.Fatalf("flows=%+v, want conn/http/tls flows", flows)
	}
	observations := readJSONLLines[analyzer.ObservationRecord](t, filepath.Join(outDir, "observations.jsonl"))
	if !zeekObservationExists(observations, "dns_query", "api.camera.example") ||
		!zeekObservationExists(observations, "http_request", "camera-cloud.example") ||
		!zeekObservationExists(observations, "tls_sni", "tls.camera.example") {
		t.Fatalf("observations=%+v, want DNS/HTTP/TLS observations", observations)
	}
	if !strings.Contains(out.String(), "Zeek import complete") {
		t.Fatalf("output=%q, want completion summary", out.String())
	}
}

func zeekObservationExists(observations []analyzer.ObservationRecord, kind, destination string) bool {
	for _, observation := range observations {
		if observation.Kind == kind && observation.ObservedDestination == destination {
			return true
		}
	}
	return false
}
