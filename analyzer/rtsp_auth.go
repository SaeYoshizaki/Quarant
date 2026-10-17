package analyzer

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// RTSP (554) is cleartext, so a camera's answers to credential attempts
// and to unauthenticated stream requests are visible on the LAN. Requests
// and responses are paired in order per connection (RTSP answers strictly
// in request order); attempts are counted per (camera, client) across
// connections, because guessing tools open many.

const (
	rtspPort = 554
	// guessReportThreshold is when a run of failed credentialed attempts is
	// reported as a candidate; the count is in the evidence.
	guessReportThreshold = 10
	guessWindow          = 10 * time.Minute
	// nistFailedAttemptLimit: NIST SP 800-63B 5.2.2 requires verifiers to
	// limit consecutive failed authentication attempts to no more than 100.
	nistFailedAttemptLimit = 100
	maxPendingRTSP         = 4096
)

var (
	rtspRequestLine = regexp.MustCompile(`(?m)^([A-Z_]+) (\S+) RTSP/1\.0\r?$`)
	rtspStatusLine  = regexp.MustCompile(`(?m)^RTSP/1\.0 (\d{3})`)
	rtspUserinfo    = regexp.MustCompile(`^rtsp://[^/@]*@`)
	rtspHost        = regexp.MustCompile(`^rtsp://[^/]*`)
	// Cameras accept credentials inside the path (e.g.
	// /user=admin_password=secret_channel=1.sdp); mask their values.
	rtspPathSecret = regexp.MustCompile(`(?i)(user|username|usr|password|passwd|pwd|pass|pw|token|auth|key|sid)=[^_&;/.]*`)
)

type rtspRequest struct {
	method string
	path   string
	auth   bool
}

type guessState struct {
	failures     []time.Time
	reportedAt   time.Time
	failedTotal  int
	successAfter bool
}

// rtspRequests splits a client segment into requests. A request whose
// headers continue in the next segment is seen without its Authorization
// header; tools send each request in one segment, so this is rare.
func rtspRequests(payload []byte) []rtspRequest {
	locs := rtspRequestLine.FindAllSubmatchIndex(payload, -1)
	out := make([]rtspRequest, 0, len(locs))
	for i, loc := range locs {
		end := len(payload)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		block := bytes.ToLower(payload[loc[1]:end])
		out = append(out, rtspRequest{
			method: string(payload[loc[2]:loc[3]]),
			path:   rtspPath(string(payload[loc[4]:loc[5]])),
			auth:   bytes.Contains(block, []byte("\nauthorization:")),
		})
	}
	return out
}

// rtspPath drops the host and any userinfo from an RTSP URL so neither
// addresses nor credentials reach the evidence.
func rtspPath(u string) string {
	u = rtspUserinfo.ReplaceAllString(u, "rtsp://")
	u = rtspHost.ReplaceAllString(u, "")
	if i := strings.IndexByte(u, '?'); i >= 0 {
		u = u[:i]
	}
	u = rtspPathSecret.ReplaceAllString(u, "$1=***")
	if u == "" {
		u = "/"
	}
	if len(u) > 60 {
		u = u[:60]
	}
	return u
}

func (h *FlowHandler) observeRTSP(now time.Time, st *FlowState, fromClient bool, payload []byte) {
	if st.DstPort != rtspPort || len(payload) == 0 {
		return
	}
	if fromClient {
		for _, r := range rtspRequests(payload) {
			if len(st.RTSPPending) < maxPendingRTSP {
				st.RTSPPending = append(st.RTSPPending, r)
			}
		}
		return
	}
	for _, m := range rtspStatusLine.FindAllSubmatch(payload, -1) {
		if len(st.RTSPPending) == 0 {
			return
		}
		req := st.RTSPPending[0]
		st.RTSPPending = st.RTSPPending[1:]
		status := string(m[1])
		ok := status[0] == '2'
		switch {
		case req.auth && status == "401":
			h.recordGuess(now, st, false)
		case req.auth && ok:
			h.recordGuess(now, st, true)
		case !req.auth && ok && (req.method == "DESCRIBE" || req.method == "PLAY"):
			h.reportUnauthenticatedStream(now, st, req, status)
		}
	}
}

func (h *FlowHandler) recordGuess(now time.Time, st *FlowState, success bool) {
	if !h.isLocal(st.DstIP) {
		return
	}
	key := st.DstIP + "|" + st.SrcIP
	if h.guesses == nil {
		h.guesses = map[string]*guessState{}
	}
	g := h.guesses[key]
	if g == nil {
		g = &guessState{}
		h.guesses[key] = g
	}
	if success {
		// A success after a reported run shows the account was not locked
		// out by those failures.
		if g.failedTotal >= guessReportThreshold && !g.successAfter {
			g.successAfter = true
			h.reportGuessing(now, st, g)
		}
		g.failures = g.failures[:0]
		return
	}
	g.failedTotal++
	g.failures = append(g.failures, now)
	cut := 0
	for cut < len(g.failures) && now.Sub(g.failures[cut]) > guessWindow {
		cut++
	}
	g.failures = g.failures[cut:]
	crossedNIST := g.failedTotal == nistFailedAttemptLimit+1
	if (len(g.failures) == guessReportThreshold && (g.reportedAt.IsZero() || now.Sub(g.reportedAt) >= time.Hour)) || crossedNIST {
		g.reportedAt = now
		h.reportGuessing(now, st, g)
	}
}

func (h *FlowHandler) reportGuessing(now time.Time, st *FlowState, g *guessState) {
	var window time.Duration
	if len(g.failures) > 0 {
		window = now.Sub(g.failures[0])
	}
	rate := float64(len(g.failures)) / maxSeconds(window)
	severity := SeverityWarning
	fact := fmt.Sprintf("%d credentialed RTSP requests from %s were refused with 401 by this device.", g.failedTotal, st.SrcIP)
	inference := "Someone is guessing credentials against the device. Continued 401 answers do not show whether the device limits attempts: a locked-out account can still be answered with 401."
	if g.successAfter {
		severity = SeverityHigh
		fact += " A later credentialed request from the same client succeeded."
		inference = "The failed attempts did not lock the client out: guessing remained possible (EN 303 645 5.1-5 asks that brute force over network interfaces be impracticable)."
	}
	event := Event{
		Timestamp:  now,
		Type:       "I1_CREDENTIAL_GUESSING_OBSERVED",
		Severity:   severity,
		RuleID:     "I1_CREDENTIAL_GUESSING_OBSERVED",
		Category:   "I1",
		FlowKey:    flowKeyTCP(st.SrcIP, st.SrcPort, st.DstIP, st.DstPort),
		Confidence: "high",
		Basis:      BasisObserved,
		DeviceKey:  st.DstIP,
		SrcIP:      st.SrcIP,
		SrcPort:    st.SrcPort,
		DstIP:      st.DstIP,
		DstPort:    st.DstPort,
		Evidence: fmt.Sprintf("protocol=rtsp client=%s failed_attempts=%d failed_in_window=%d window_s=%.0f rate_per_s=%.1f exceeds_nist_800_63b_limit=%t success_after_failures=%t",
			st.SrcIP, g.failedTotal, len(g.failures), window.Seconds(), rate, g.failedTotal > nistFailedAttemptLimit, g.successAfter),
		ObservedFact:   fact,
		Inference:      inference,
		Limitation:     "Only RTSP is examined. Lockout that keeps answering 401, and limits applied to other clients or interfaces, are not visible; credentials themselves are not read.",
		Recommendation: "Find the client making the attempts. Use a strong, unique camera password and check whether the device offers attempt limiting.",
		Message:        "Repeated failed credential attempts against the device were observed.",
	}
	h.enrichEvent(&event)
	_ = h.eventSink.Write(event)
}

func (h *FlowHandler) reportUnauthenticatedStream(now time.Time, st *FlowState, req rtspRequest, status string) {
	ruleID := "I3_UNAUTHENTICATED_STREAM_ACCESS"
	if !h.isLocal(st.DstIP) {
		return
	}
	// Once per (device, client) and hour: URL-guessing tools open one
	// connection per path.
	key := ruleID + "|" + st.DstIP + "|" + st.SrcIP
	if last, ok := h.streamReported[key]; ok && now.Sub(last) < time.Hour {
		return
	}
	if h.streamReported == nil {
		h.streamReported = map[string]time.Time{}
	}
	h.streamReported[key] = now
	event := Event{
		Timestamp:      now,
		Type:           ruleID,
		Severity:       SeverityWarning,
		RuleID:         ruleID,
		Category:       "I3",
		FlowKey:        flowKeyTCP(st.SrcIP, st.SrcPort, st.DstIP, st.DstPort),
		Confidence:     "high",
		DeviceKey:      st.DstIP,
		SrcIP:          st.SrcIP,
		SrcPort:        st.SrcPort,
		DstIP:          st.DstIP,
		DstPort:        st.DstPort,
		Evidence:       fmt.Sprintf("protocol=rtsp method=%s path=%s status=%s credentials=none_visible client=%s", req.method, req.path, status, st.SrcIP),
		ObservedFact:   fmt.Sprintf("An RTSP %s without an Authorization header was answered with %s.", req.method, status),
		Inference:      "The device's media stream may be available to any host on the network without authentication.",
		Limitation:     "Access may be restricted by network position or an allow-list that is not visible; a 200 to DESCRIBE shows the stream description was served, not that video was watched.",
		Recommendation: "Enable RTSP authentication on the device, or disable RTSP if it is not used.",
		Message:        "Media stream request was served without authentication.",
	}
	h.enrichEvent(&event)
	_ = h.eventSink.Write(event)
}

func maxSeconds(d time.Duration) float64 {
	if d < time.Second {
		return 1
	}
	return d.Seconds()
}
