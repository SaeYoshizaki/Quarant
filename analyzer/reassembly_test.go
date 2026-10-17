package analyzer

import "testing"

func feed(a *streamAssembler, segs ...struct {
	seq uint32
	p   string
}) string {
	var out []byte
	for _, s := range segs {
		out = append(out, a.add(s.seq, []byte(s.p))...)
	}
	return string(out)
}

type seg = struct {
	seq uint32
	p   string
}

func TestAssemblerInOrder(t *testing.T) {
	var a streamAssembler
	a.syn(99)
	if got := feed(&a, seg{100, "GET / "}, seg{106, "HTTP/1.1\r\n"}); got != "GET / HTTP/1.1\r\n" {
		t.Fatalf("got %q", got)
	}
	if a.RetransmittedBytes != 0 || a.Gaps != 0 {
		t.Fatalf("counters %+v", a)
	}
}

func TestAssemblerDropsRetransmissions(t *testing.T) {
	var a streamAssembler
	a.syn(0)
	got := feed(&a, seg{1, "abcd"}, seg{1, "abcd"}, seg{3, "cdef"}, seg{7, "g"})
	if got != "abcdefg" {
		t.Fatalf("got %q", got)
	}
	if a.RetransmittedBytes != 6 {
		t.Fatalf("retransmitted %d, want 6", a.RetransmittedBytes)
	}
}

func TestAssemblerReorders(t *testing.T) {
	var a streamAssembler
	a.syn(0)
	got := feed(&a, seg{1, "ab"}, seg{5, "ef"}, seg{3, "cd"})
	if got != "abcdef" {
		t.Fatalf("got %q", got)
	}
	if a.Gaps != 0 {
		t.Fatalf("gaps %d", a.Gaps)
	}
}

func TestAssemblerSkipsGapProvenByAck(t *testing.T) {
	var a streamAssembler
	a.syn(0)
	if got := feed(&a, seg{1, "ab"}, seg{5, "ef"}); got != "ab" {
		t.Fatalf("before ack: %q", got)
	}
	// The receiver acknowledges up to 7: "cd" reached it but not the capture.
	if got := string(a.ack(7)); got != "ef" {
		t.Fatalf("after ack: %q", got)
	}
	if a.Gaps != 1 || a.GapBytes != 2 {
		t.Fatalf("gap counters %+v", a)
	}
}

func TestAssemblerAckBeforeSegmentSkipsGap(t *testing.T) {
	var a streamAssembler
	a.syn(0)
	a.add(1, []byte("ab"))
	a.ack(9) // receiver already has bytes 3..8
	if got := string(a.add(7, []byte("gh"))); got != "gh" {
		t.Fatalf("got %q", got)
	}
	if a.Gaps != 1 || a.GapBytes != 4 {
		t.Fatalf("gap counters %+v", a)
	}
}

func TestAssemblerBoundsPendingSegments(t *testing.T) {
	var a streamAssembler
	a.syn(0)
	a.add(1, []byte("a"))
	var out []byte
	for i := 0; i <= maxPendingSegments; i++ {
		out = append(out, a.add(uint32(10+i), []byte("x"))...)
	}
	if len(out) != maxPendingSegments+1 || a.Gaps != 1 {
		t.Fatalf("released %d bytes, gaps %d", len(out), a.Gaps)
	}
}

func TestAssemblerMidStreamAndWraparound(t *testing.T) {
	var a streamAssembler
	start := uint32(0xfffffffe)
	got := feed(&a, seg{start, "ab"}, seg{start + 4, "ef"}, seg{start + 2, "cd"})
	if got != "abcdef" {
		t.Fatalf("got %q", got)
	}
}

func TestAssemblerRestartsOnImplausibleJump(t *testing.T) {
	var a streamAssembler
	a.syn(0)
	got := feed(&a, seg{1, "ab"}, seg{1 + 3*maxSeqWindow, "zz"})
	if got != "abzz" {
		t.Fatalf("got %q", got)
	}
}
