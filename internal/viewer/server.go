package viewer

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"quarant/internal/reportapi"
)

type Options struct {
	EventsPath    string
	ReportPath    string
	FlowsPath     string
	InventoryPath string
	Addr          string
	OpenBrowser   bool
	WebDist       string
}

func Serve(opts Options) error {
	if strings.TrimSpace(opts.EventsPath) == "" {
		opts.EventsPath = "events.jsonl"
	}
	if strings.TrimSpace(opts.FlowsPath) == "" {
		opts.FlowsPath = "flows.jsonl"
	}
	if strings.TrimSpace(opts.InventoryPath) == "" {
		opts.InventoryPath = "device_inventory.json"
	}
	if strings.TrimSpace(opts.Addr) == "" {
		opts.Addr = "127.0.0.1:8080"
	}
	if strings.TrimSpace(opts.WebDist) == "" {
		opts.WebDist = filepath.Join("web", "out")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) {
		sourcePath := opts.EventsPath
		if opts.ReportPath != "" {
			sourcePath = opts.ReportPath
		}
		rep, err := reportapi.LoadReport(sourcePath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, rep)
	})
	mux.HandleFunc("/api/activity/summary", func(w http.ResponseWriter, r *http.Request) {
		rep, err := reportapi.LoadActivitySummary(opts.EventsPath, opts.FlowsPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, rep)
	})
	mux.HandleFunc("/api/inventory", func(w http.ResponseWriter, r *http.Request) {
		rep, err := reportapi.LoadInventory(opts.InventoryPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, rep)
	})
	mux.HandleFunc("/api/flows", func(w http.ResponseWriter, r *http.Request) {
		rep, err := reportapi.LoadFlows(opts.FlowsPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, rep)
	})

	listener, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	viewerURL := "http://" + listener.Addr().String()
	staticServed := attachUIRoutes(mux, opts.WebDist, viewerURL)

	log.Printf("quarant api listening on %s", viewerURL)
	log.Printf("reading events from %s", opts.EventsPath)
	if opts.ReportPath != "" {
		log.Printf("reading report from %s", opts.ReportPath)
	}
	log.Printf("reading flows from %s", opts.FlowsPath)
	log.Printf("reading inventory from %s", opts.InventoryPath)
	if staticServed {
		log.Printf("serving report viewer from %s", opts.WebDist)
	} else {
		log.Printf("web UI export not found at %s", opts.WebDist)
		log.Printf("build the web UI once with: cd web && NEXT_PUBLIC_API_BASE_URL=%s npm run build", viewerURL)
	}
	if opts.OpenBrowser {
		go func(url string) {
			time.Sleep(250 * time.Millisecond)
			if err := openBrowser(url); err != nil {
				log.Printf("open browser: %v", err)
			}
		}(viewerURL)
	}
	return http.Serve(listener, withCORS(mux))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func attachUIRoutes(mux *http.ServeMux, webDist, viewerURL string) bool {
	if webDist != "" {
		if info, err := os.Stat(webDist); err == nil && info.IsDir() {
			fileServer := http.FileServer(http.Dir(webDist))
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/healthz" {
					http.NotFound(w, r)
					return
				}
				requestPath := strings.TrimPrefix(pathClean(r.URL.Path), "/")
				if requestPath == "" {
					requestPath = "index.html"
				}
				fullPath := filepath.Join(webDist, requestPath)
				if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
					fileServer.ServeHTTP(w, r)
					return
				}
				http.ServeFile(w, r, filepath.Join(webDist, "index.html"))
			})
			return true
		}
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = viewerHintTemplate.Execute(w, struct {
			ViewerURL string
			WebDist   string
		}{
			ViewerURL: viewerURL,
			WebDist:   webDist,
		})
	})
	return false
}

func pathClean(path string) string {
	cleaned := filepath.ToSlash(filepath.Clean("/" + path))
	if cleaned == "." {
		return "/"
	}
	return cleaned
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	return cmd.Start()
}

var viewerHintTemplate = template.Must(template.New("viewer-hint").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Quarant Report Viewer</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: #f8fafc; color: #0f172a; }
    main { max-width: 920px; margin: 48px auto; padding: 0 24px; }
    section { background: white; border: 1px solid #d0d5dd; padding: 24px; margin-bottom: 16px; }
    h1 { margin: 0 0 12px; font-size: 36px; }
    h2 { margin: 0 0 10px; font-size: 18px; }
    p, li { line-height: 1.6; color: #475467; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #f8fafc; }
    pre { padding: 12px; border: 1px solid #e4e7ec; overflow-x: auto; }
  </style>
</head>
<body>
  <main>
    <section>
      <h1>Quarant Report Viewer</h1>
      <p>The API is running, but the exported web UI was not found at <code>{{ .WebDist }}</code>.</p>
      <p>Build the existing Next.js viewer once, then rerun the same command.</p>
    </section>
    <section>
      <h2>Build Once</h2>
      <pre>cd web
NEXT_PUBLIC_API_BASE_URL={{ .ViewerURL }} npm run build</pre>
    </section>
    <section>
      <h2>Then Launch</h2>
      <pre>./quarant report report.json --open</pre>
    </section>
  </main>
</body>
</html>`))
