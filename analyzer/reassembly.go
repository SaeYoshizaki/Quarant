package analyzer

import "sort"

// streamAssembler puts one direction of a TCP connection back into sequence
// order before its bytes reach the flow buffer. Appending segments in arrival
// order duplicated retransmitted bytes and misplaced reordered ones in
// 7-23% of the HTTP streams of the UNSW captures (quarant parser-diff),
// which the body rules (credentials, PII) then read.
//
// Capture loss is detected from the other direction: when the receiver
// acknowledges bytes that never appeared in the capture, the gap cannot fill,
// so the assembler skips it and counts it instead of waiting. Without that
// evidence it waits for at most maxPendingSegments out-of-order segments.
type streamAssembler struct {
	synSeen   bool
	startSeen bool // a segment carrying the first stream byte was seen
	isn       uint32
	started   bool
	next      uint32 // next expected sequence number
	maxAck    uint32 // highest acknowledgement seen from the receiver
	ackSeen   bool
	pending   map[uint32][]byte

	RetransmittedBytes int
	Gaps               int
	GapBytes           int
}

const (
	maxPendingSegments = 8
	// maxSeqWindow bounds how far ahead a segment may start: anything
	// further is treated as a new start (port reuse or a broken sequence).
	maxSeqWindow = 1 << 20
)

func seqDiff(a, b uint32) int32 { return int32(a - b) }

// syn records the initial sequence number from a SYN or SYN/ACK.
func (a *streamAssembler) syn(seq uint32) {
	if a.started {
		return
	}
	a.started = true
	a.synSeen = true
	a.isn = seq
	a.next = seq + 1
}

// isStreamStart reports whether a segment at seq carries the first byte of
// the stream. Without a SYN the first segment seen is taken as the start.
func (a *streamAssembler) isStreamStart(seq uint32, firstPayloadSeen bool) bool {
	if a.synSeen {
		return seq == a.isn+1
	}
	return firstPayloadSeen
}

// markStart records that the stream start was seen (call for every client
// segment before routing it).
func (a *streamAssembler) markStart(seq uint32) {
	if a.synSeen && seq == a.isn+1 {
		a.startSeen = true
	}
}

// ack records an acknowledgement sent by the receiver of this direction and
// returns bytes released by skipping a gap the receiver proved to be capture
// loss.
func (a *streamAssembler) ack(ackNum uint32) []byte {
	if !a.ackSeen || seqDiff(ackNum, a.maxAck) > 0 {
		a.maxAck, a.ackSeen = ackNum, true
	}
	return a.skipLostGap()
}

// add takes one segment and returns the bytes that are now in order.
func (a *streamAssembler) add(seq uint32, payload []byte) []byte {
	if len(payload) == 0 {
		return nil
	}
	if !a.started {
		// Picked up mid-connection: start at the first segment seen.
		a.started = true
		a.next = seq
	}
	off := seqDiff(seq, a.next)
	switch {
	case off > maxSeqWindow || off < -maxSeqWindow:
		// Not plausibly the same byte stream: restart from here rather
		// than buffer or drop everything that follows.
		a.next = seq
		a.pending = nil
		off = 0
	case off < 0:
		dup := int(-off)
		if dup >= len(payload) {
			a.RetransmittedBytes += len(payload)
			return nil
		}
		a.RetransmittedBytes += dup
		payload = payload[dup:]
		seq = a.next
		off = 0
	}
	if off > 0 {
		if a.pending == nil {
			a.pending = map[uint32][]byte{}
		}
		if prev, ok := a.pending[seq]; ok {
			if len(prev) >= len(payload) {
				a.RetransmittedBytes += len(payload)
				return a.skipLostGap()
			}
			a.RetransmittedBytes += len(prev)
		}
		a.pending[seq] = append([]byte(nil), payload...)
		if len(a.pending) > maxPendingSegments {
			return a.skipGap()
		}
		return a.skipLostGap()
	}
	out := append([]byte(nil), payload...)
	a.next += uint32(len(payload))
	return append(out, a.drain()...)
}

// hold keeps a segment that arrived ahead of the stream start while the
// flow is not yet known to need its payload (the protocol is recognised from
// the first bytes), so that it is not lost once the start arrives.
func (a *streamAssembler) hold(seq uint32, payload []byte) {
	if a.startSeen && a.next == a.isn+1 {
		// The start arrived and the flow was not captured: nothing to keep.
		a.pending = nil
		return
	}
	if !a.synSeen || a.startSeen || a.next != a.isn+1 || len(payload) == 0 || len(a.pending) >= maxPendingSegments {
		return
	}
	if off := seqDiff(seq, a.next); off <= 0 || off > maxSeqWindow {
		return
	}
	if a.pending == nil {
		a.pending = map[uint32][]byte{}
	}
	a.pending[seq] = append([]byte(nil), payload...)
}

// drain releases pending segments that have become contiguous.
func (a *streamAssembler) drain() []byte {
	var out []byte
	for len(a.pending) > 0 {
		progressed := false
		for _, seq := range a.pendingOrder() {
			seg := a.pending[seq]
			off := seqDiff(seq, a.next)
			if off > 0 {
				break
			}
			delete(a.pending, seq)
			progressed = true
			dup := int(-off)
			if dup >= len(seg) {
				a.RetransmittedBytes += len(seg)
				continue
			}
			a.RetransmittedBytes += dup
			out = append(out, seg[dup:]...)
			a.next += uint32(len(seg) - dup)
		}
		if !progressed {
			break
		}
	}
	return out
}

func (a *streamAssembler) pendingOrder() []uint32 {
	seqs := make([]uint32, 0, len(a.pending))
	for q := range a.pending {
		seqs = append(seqs, q)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqDiff(seqs[i], a.next) < seqDiff(seqs[j], a.next) })
	return seqs
}

// skipLostGap skips the gap before the earliest pending segment when the
// receiver has acknowledged past it.
func (a *streamAssembler) skipLostGap() []byte {
	if len(a.pending) == 0 || !a.ackSeen {
		return nil
	}
	first := a.pendingOrder()[0]
	if seqDiff(a.maxAck, first) < 0 {
		return nil
	}
	return a.skipGap()
}

// skipGap gives up on the missing bytes before the earliest pending segment.
func (a *streamAssembler) skipGap() []byte {
	if len(a.pending) == 0 {
		return nil
	}
	first := a.pendingOrder()[0]
	a.Gaps++
	a.GapBytes += int(seqDiff(first, a.next))
	a.next = first
	return a.drain()
}
