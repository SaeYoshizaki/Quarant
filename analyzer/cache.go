package analyzer

import (
	"sync"
	"time"

	"quarant/analyzer/rules"
)

type FlowState struct {
	FirstSeen time.Time
	LastSeen  time.Time

	ClientData []byte
	ServerData []byte

	Reported map[string]bool

	DstIP   string
	DstPort uint16

	TLSClientSeen bool
	TLSClientInfo *rules.TLSClientHelloInfo

	TLSServerSeen bool
	TLSServerInfo *rules.TLSServerInfo

	DNSNames []string
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

func (c *FlowCache) Cleanup(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for k, st := range c.m {
		if now.Sub(st.LastSeen) > c.ttl {
			delete(c.m, k)
		}
	}
}
