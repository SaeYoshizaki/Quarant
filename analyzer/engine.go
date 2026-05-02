package analyzer

import (
	"fmt"
	"io"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type PacketHandler interface {
	HandlePacket(gopacket.Packet)
}

type Engine struct {
	handler PacketHandler
}

func NewEngine(handler PacketHandler) *Engine {
	return &Engine{
		handler: handler,
	}
}

func (e *Engine) RunLive(interfaceName string) error {
	handle, err := pcap.OpenLive(interfaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	log.Println("listening on", interfaceName)
	return e.runPacketSource(packetSource)
}

func (e *Engine) RunOffline(path string) error {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	log.Println("reading pcap", path)
	return e.runPacketSource(packetSource)
}

func (e *Engine) RunPCAPStream(r io.Reader) error {
	reader, err := pcapgo.NewReader(r)
	if err != nil {
		return fmt.Errorf("open stdin pcap stream: %w", err)
	}

	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())

	log.Println("reading pcap stream from stdin")
	if err := e.runPacketSource(packetSource); err != nil {
		return err
	}
	log.Println("stdin pcap stream ended")
	return nil
}

func (e *Engine) runPacketSource(packetSource *gopacket.PacketSource) error {
	for {
		packet, err := packetSource.NextPacket()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		e.handler.HandlePacket(packet)
	}
}
