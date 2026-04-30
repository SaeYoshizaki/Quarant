package analyzer

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Engine struct {
	handler *FlowHandler
}

func NewEngine(handler *FlowHandler) *Engine {
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

	return e.runHandle(handle, "listening on "+interfaceName)
}

func (e *Engine) RunOffline(path string) error {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return err
	}
	defer handle.Close()

	return e.runHandle(handle, "reading pcap "+path)
}

func (e *Engine) runHandle(handle *pcap.Handle, status string) error {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	log.Println(status)
	for packet := range packetSource.Packets() {
		e.handler.HandlePacket(packet)
	}
	return nil
}
