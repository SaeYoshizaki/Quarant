package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"unicode"

	ahocorasick "github.com/anknown/ahocorasick"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)
var matcher *ahocorasick.Machine
func initMatcher(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil{
		return err
	}
	defer file.Close()
	var patterns [][]rune
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" {
			patterns = append(patterns, []rune(strings.ToLower(word)))
		}
	}
	m := new(ahocorasick.Machine)
	if err := m.Build(patterns); err != nil {
		return err
	}
	matcher = m
	return nil
}


var keywords = []string{"password", "passwd", "login", "user", "auth", "secret"}

func isSafe(packet gopacket.Packet) bool {
	if packet.Layer(layers.LayerTypeTCP) == nil {
		return true
	}

	if packet.Layer(layers.LayerTypeTLS) != nil {
		return  true
	}
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return true
	}
	payload := appLayer.Payload()

	if isPrintable(payload) {
		lowerPayload := strings.ToLower(string(payload))
		runes := []rune(lowerPayload)
		hits := matcher.MultiPatternSearch(runes, false)

		if len(hits) > 0 {
			fmt.Println("機密ワードを検出")
			return false
		}

		for _, keyword := range keywords {
			if strings.Contains(lowerPayload, keyword){
				fmt.Printf("パスワードが平文で送られています！")
				fmt.Printf("%s", keyword)
				if netLayer := packet.NetworkLayer(); netLayer != nil {
					fmt.Printf("詳細：%s", netLayer.NetworkFlow())
				}
				return false
			}
		}
	}
	
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		if ip.DstIP.String() == "8.8.8.8" {
			return false
		}
		fmt.Printf("送信元: %s -> 送信先: %s\n", ip.SrcIP, ip.DstIP)
	}
	return true
}

func isPrintable(data []byte) bool {
	if len(data) == 0{
		return false
	}
	for i, b := range data {
		if i > 100 {break}
		if b > unicode.MaxASCII { return false }
		if !unicode.IsPrint(rune(b)) && !unicode.IsSpace((rune(b))) {
			return false
		}
	}
	return true
}

func main() {
	inInterface := "eth1"
	outInterface := "eth2"

	inHandle, err := pcap.OpenLive(inInterface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("入力側の準備に失敗: ", err)
	}
	defer inHandle.Close()

	outHandle, err := pcap.OpenLive(outInterface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("出力側の準備に失敗: ", err)
	}
	defer outHandle.Close()

	packetSource := gopacket.NewPacketSource(inHandle, inHandle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println("パケットを受け取りました")
		if isSafe(packet) {
			data := packet.Data()
			err := outHandle.WritePacketData(data)
			if err != nil {
				log.Println("転送失敗：", err)
			}
		} else {
			fmt.Println("ブロックしました:", packet)
		}
	}
}
