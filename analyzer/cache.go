package analyzer

import (
	"sync"
	"time"
)

type FlowState struct {
	FirstSeen time.Time
	LastSeen  time.Time

	Data         []byte
	FlowReported bool
	HTTPReported bool
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
			Data:      make([]byte, 0, 1024),
		}
		c.m[key] = st
		return st
	}
	st.LastSeen = now
	return st
}

func (c *FlowCache) AppendUpToLimit(st *FlowState, chunk []byte) {
	if len(chunk) == 0 {
		return
	}
	remain := c.maxSize - len(st.Data)
	if remain <= 0 {
		return
	}

	if len(chunk) > remain {
		chunk = chunk[:remain]
	}
	st.Data = append(st.Data, chunk...)
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
