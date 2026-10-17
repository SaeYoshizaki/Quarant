package parserdiff

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"quarant/analyzer/rules"
)

func TestInspectCorpus(t *testing.T) {
	path := os.Getenv("QDIFF_INPUT")
	if path == "" {
		t.Skip()
	}
	raw, _ := os.ReadFile(path)
	line := strings.Split(string(raw), "\n")[1]
	s, err := strconv.Unquote(strings.TrimSuffix(strings.TrimPrefix(line, "[]byte("), ")"))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(s)
	t.Logf("len=%d hex=% x", len(data), data[:min(len(data), 80)])
	info, ok := rules.DetectTLSClientHello(data)
	t.Logf("quarant ok=%v %+v", ok, info)
	_, rerr := ReferenceClientHelloErr(data)
	t.Logf("reference ok=%v err=%v", rerr == nil, rerr)
}

// TestBlameExtension removes each extension in turn and reports which removal
// makes the reference accept the hello.
func TestBlameExtension(t *testing.T) {
	path := os.Getenv("QDIFF_INPUT")
	if path == "" {
		t.Skip()
	}
	raw, _ := os.ReadFile(path)
	line := strings.Split(string(raw), "\n")[1]
	s, _ := strconv.Unquote(strings.TrimSuffix(strings.TrimPrefix(line, "[]byte("), ")"))
	data := []byte(s)
	for _, typ := range []uint16{0, 5, 10, 11, 13, 16, 18, 23, 35, 43, 45, 50, 51, 65281} {
		if mod, ok := withoutExtension(data, typ); ok {
			_, err := ReferenceClientHelloErr(mod)
			t.Logf("without %d: reference err=%v", typ, err)
		}
	}
}

func TestDumpStructure(t *testing.T) {
	path := os.Getenv("QDIFF_INPUT")
	if path == "" {
		t.Skip()
	}
	raw, _ := os.ReadFile(path)
	line := strings.Split(string(raw), "\n")[1]
	s, _ := strconv.Unquote(strings.TrimSuffix(strings.TrimPrefix(line, "[]byte("), ")"))
	b := []byte(s)
	rl := int(b[3])<<8 | int(b[4])
	hl := int(b[6])<<16 | int(b[7])<<8 | int(b[8])
	t.Logf("total=%d recordLen=%d avail=%d hsLen=%d", len(b), rl, len(b)-5, hl)
	ch := b[9 : 9+hl]
	i := 34
	i += 1 + int(ch[i])
	cs := int(ch[i])<<8 | int(ch[i+1])
	i += 2 + cs
	i += 1 + int(ch[i])
	el := int(ch[i])<<8 | int(ch[i+1])
	i += 2
	t.Logf("extLen=%d remainingInHello=%d", el, len(ch)-i)
	exts := ch[i : i+el]
	for j := 0; j+4 <= len(exts); {
		typ := int(exts[j])<<8 | int(exts[j+1])
		l := int(exts[j+2])<<8 | int(exts[j+3])
		end := j + 4 + l
		if end > len(exts) {
			end = len(exts)
		}
		head := exts[j+4 : end]
		if len(head) > 12 {
			head = head[:12]
		}
		t.Logf(" ext %d len %d % x", typ, l, head)
		j += 4 + l
	}
	_, ok := withoutExtension(b, 51)
	t.Logf("withoutExtension(51) ok=%v", ok)
}

func TestDumpReference(t *testing.T) {
	path := os.Getenv("QDIFF_INPUT")
	if path == "" {
		t.Skip()
	}
	raw, _ := os.ReadFile(path)
	line := strings.Split(string(raw), "\n")[1]
	s, _ := strconv.Unquote(strings.TrimSuffix(strings.TrimPrefix(line, "[]byte("), ")"))
	b := []byte(s)
	h, err := ReferenceClientHelloErr(b)
	t.Logf("reference err=%v hello=%+v", err, h)
	ch := b[9:]
	sid := int(ch[34])
	i := 35 + sid
	t.Logf("sidLen=%d cipherLenField=% x", sid, ch[i:i+2])
}
