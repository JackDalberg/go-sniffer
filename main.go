package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const ROTMGPort uint16 = 2050

var (
	snapshot_len int32         = 1024
	promiscuous  bool          = false
	timeout      time.Duration = 60 * time.Millisecond //pcap.BlockForever

	handle *pcap.Handle

	tcpLayer layers.TCP
	ipLayer  layers.IPv4
	ethLayer layers.Ethernet
)

/*
Finds device communicating on ROTMGPort (2050) with TCP and  returns a pcap.Handle to said device
*/
func FindROTMGDevice() *pcap.Handle {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("No device", err)
	}

	handleChan := make(chan *pcap.Handle)
	defer close(handleChan)
	ctx, cancel := context.WithCancel(context.Background())

	for _, device := range devices {
		if len(device.Addresses) == 0 {
			continue
		}
		fmt.Printf("Trying device: %v\n", device)
		go func(device pcap.Interface) {
			// fmt.Printf("Trying device: %v\n", device.Name)

			handle, err := pcap.OpenLive(device.Name, snapshot_len, promiscuous, timeout)
			if err != nil {
				log.Fatal(err)
			}
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			packetChan := packetSource.Packets()
			for {
				select {
				case <-ctx.Done():
					handle.Close()
					fmt.Printf("Closed device: %v\n\n", device)
					return

				case packet := <-packetChan:
					tcpLayer := packet.Layer(layers.LayerTypeTCP)
					if tcpLayer != nil {
						tcp, _ := tcpLayer.(*layers.TCP)
						if uint16(tcp.SrcPort) == ROTMGPort || uint16(tcp.DstPort) == ROTMGPort {
							handleChan <- handle
							return
						}
					}

				default:
					time.Sleep(10 * time.Millisecond)
				}
			}

		}(device)
	}
	handle := <-handleChan
	cancel()
	return handle

}

func main() {
	handle = FindROTMGDevice()

	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&ethLayer,
			&ipLayer,
			&tcpLayer,
		)
		foundLayerTypes := []gopacket.LayerType{}

		err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		if err != nil {
			fmt.Println("Trouble decoding layers: ", err)
		}

		for _, layerType := range foundLayerTypes {
			if layerType == layers.LayerTypeTCP && (uint16(tcpLayer.SrcPort) == ROTMGPort || uint16(tcpLayer.DstPort) == ROTMGPort) {
				fmt.Println("TCP Port: ", tcpLayer.SrcPort, "->", tcpLayer.DstPort)
				// fmt.Println(packet)
				// fmt.Println(packet.TransportLayer().LayerContents())
			}
		}
	}
}
