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
	return &Engine {
		handler: handler,
	}
}

func (e *Engine) Run(interfaceName string) error {
	handle, err := pcap.OpenLive(interfaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	log.Println("listening on", interfaceName)
	for packet := range packetSource.Packets() {
		e.handler.HandlePacket(packet)
	}
	return nil
}