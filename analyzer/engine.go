package analyzer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type PacketHandler interface {
	HandlePacket(gopacket.Packet)
}

// Flusher is implemented by handlers that keep per-flow state and need to emit
// final records when the input ends (end of PCAP, or live capture stopped).
// at is the capture timestamp of the last packet seen, or the wall clock for
// live capture when no packet has been seen.
type Flusher interface {
	Flush(at time.Time)
}

type Engine struct {
	handler        PacketHandler
	lastPacketTime time.Time
	packets        int
}

func NewEngine(handler PacketHandler) *Engine {
	return &Engine{
		handler: handler,
	}
}

// PacketsProcessed reports how many packets were handed to the handler.
func (e *Engine) PacketsProcessed() int {
	return e.packets
}

func (e *Engine) RunLive(interfaceName string) error {
	return e.RunLiveContext(context.Background(), interfaceName)
}

// RunLiveContext captures until ctx is cancelled. A short read timeout is used
// instead of pcap.BlockForever so that cancellation is observed promptly and
// the handler can flush open flows before the process exits.
func (e *Engine) RunLiveContext(ctx context.Context, interfaceName string) error {
	handle, err := pcap.OpenLive(interfaceName, 65535, true, 500*time.Millisecond)
	if err != nil {
		return err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	log.Println("listening on", interfaceName)
	err = e.runPacketSource(ctx, packetSource)
	at := e.lastPacketTime
	if at.IsZero() {
		at = time.Now()
	}
	e.flush(at)
	return err
}

func (e *Engine) RunOffline(path string) error {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	log.Println("reading pcap", path)
	err = e.runPacketSource(context.Background(), packetSource)
	e.flush(e.lastPacketTime)
	return err
}

func (e *Engine) RunPCAPStream(r io.Reader) error {
	reader, err := pcapgo.NewReader(r)
	if err != nil {
		return fmt.Errorf("open stdin pcap stream: %w", err)
	}

	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())

	log.Println("reading pcap stream from stdin")
	err = e.runPacketSource(context.Background(), packetSource)
	e.flush(e.lastPacketTime)
	if err != nil {
		return err
	}
	log.Println("stdin pcap stream ended")
	return nil
}

func (e *Engine) flush(at time.Time) {
	if f, ok := e.handler.(Flusher); ok {
		f.Flush(at)
	}
}

func (e *Engine) runPacketSource(ctx context.Context, packetSource *gopacket.PacketSource) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		packet, err := packetSource.NextPacket()
		if err != nil {
			if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
				// A truncated final record (common when a capture is cut off)
				// ends the input; everything before it has been processed.
				return nil
			}
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			return err
		}
		if md := packet.Metadata(); md != nil && !md.Timestamp.IsZero() {
			e.lastPacketTime = md.Timestamp
		}
		e.packets++
		e.handler.HandlePacket(packet)
	}
}
