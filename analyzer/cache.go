package analyzer

import (
	"sort"
	"sync"
	"time"

	"quarant/analyzer/rules"
)

type FlowState struct {
	FirstSeen time.Time
	LastSeen  time.Time

	ClientData []byte
	ServerData []byte
	// ClientAsm and ServerAsm restore sequence order (and count
	// retransmissions and capture gaps) for the captured directions.
	ClientAsm streamAssembler
	ServerAsm streamAssembler

	Reported map[string]bool

	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16

	PacketCount int
	ClientBytes int64
	ServerBytes int64

	// ServerResponded is set once the responder sent SYN/ACK or payload,
	// i.e. a service actually answered (a bare SYN proves nothing).
	ServerResponded bool
	HTTPEnriched    bool
	// TLSByContent: the client's first payload is a TLS ClientHello record,
	// whatever the port.
	TLSByContent bool
	// HTTPByContent: the client's first payload is an HTTP request to a
	// local server on a port outside rules.IsHTTPPort (UPnP control).
	HTTPByContent bool
	// RTSPPending holds this connection's RTSP requests awaiting an answer.
	RTSPPending []rtspRequest

	TLSClientSeen bool
	TLSClientInfo *rules.TLSClientHelloInfo

	TLSServerSeen bool
	TLSServerInfo *rules.TLSServerInfo

	HTTPSeen   bool
	HTTPHost   string
	HTTPMethod string
	HTTPPath   string

	MQTTSeen   bool
	TelnetSeen bool

	LastFlowLogAt           time.Time
	LastFlowMetaFingerprint string

	DNSNames []string
}

func (st *FlowState) AlreadyReported(ruleID string) bool {
	if st == nil || ruleID == "" {
		return false
	}
	return st.Reported[ruleID]
}

func (st *FlowState) MarkReported(ruleID string) {
	if st == nil || ruleID == "" {
		return
	}
	if st.Reported == nil {
		st.Reported = make(map[string]bool)
	}
	st.Reported[ruleID] = true
}

type FlowCache struct {
	mu      sync.Mutex
	maxSize int
	ttl     time.Duration
	m       map[string]*FlowState
}

func NewFlowCache(maxBytes int, ttl time.Duration) *FlowCache {
	return &FlowCache{
		maxSize: maxBytes,
		ttl:     ttl,
		m:       make(map[string]*FlowState),
	}
}

func (c *FlowCache) GetOrCreate(key string, now time.Time) *FlowState {
	c.mu.Lock()
	defer c.mu.Unlock()

	st, ok := c.m[key]
	if !ok {
		st = &FlowState{
			FirstSeen: now,
			LastSeen:  now,
			Reported:  make(map[string]bool),
		}
		c.m[key] = st
		return st
	}

	st.LastSeen = now
	return st
}

func (c *FlowCache) AppendClientUpToLimit(st *FlowState, chunk []byte) {
	if len(chunk) == 0 {
		return
	}
	remain := c.maxSize - len(st.ClientData)
	if remain <= 0 {
		return
	}
	if len(chunk) > remain {
		chunk = chunk[:remain]
	}
	st.ClientData = append(st.ClientData, chunk...)
}

// AppendClientSegment passes a client segment through the assembler and
// appends the bytes that are now in order, up to the buffer limit.
func (c *FlowCache) AppendClientSegment(st *FlowState, seq uint32, payload []byte) {
	if len(st.ClientData) >= c.maxSize {
		return
	}
	c.AppendClientUpToLimit(st, st.ClientAsm.add(seq, payload))
}

// AppendServerSegment is AppendClientSegment for the server direction.
func (c *FlowCache) AppendServerSegment(st *FlowState, seq uint32, payload []byte) {
	if len(st.ServerData) >= c.maxSize {
		return
	}
	c.AppendServerUpToLimit(st, st.ServerAsm.add(seq, payload))
}

func (c *FlowCache) AppendServerUpToLimit(st *FlowState, chunk []byte) {
	if len(chunk) == 0 {
		return
	}
	remain := c.maxSize - len(st.ServerData)
	if remain <= 0 {
		return
	}
	if len(chunk) > remain {
		chunk = chunk[:remain]
	}
	st.ServerData = append(st.ServerData, chunk...)
}

func (c *FlowCache) Cleanup(now time.Time, onEvict func(string, *FlowState)) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for k, st := range c.m {
		if now.Sub(st.LastSeen) > c.ttl {
			if onEvict != nil {
				onEvict(k, st)
			}
			delete(c.m, k)
		}
	}
}

// Drain removes every flow from the cache, calling onEvict for each one in a
// stable key order.
func (c *FlowCache) Drain(onEvict func(string, *FlowState)) {
	c.mu.Lock()
	defer c.mu.Unlock()

	keys := make([]string, 0, len(c.m))
	for k := range c.m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if onEvict != nil {
			onEvict(k, c.m[k])
		}
		delete(c.m, k)
	}
}
