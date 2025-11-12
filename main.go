package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const ROTMGPort uint16 = 2050

var (
	snapshot_len int32         = 1600
	timeout      time.Duration = 50 * time.Millisecond //pcap.BlockForever
)

// Finds device communicating on ROTMGPort (2050) with TCP.
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
		go TestDevice(ctx, device, handleChan)
	}

	handle := <-handleChan
	const filter = "tcp and port 2050"
	handle.SetBPFFilter(filter)
	cancel()
	return handle
}

func TestDevice(ctx context.Context, device pcap.Interface, outChan chan<- *pcap.Handle) {
	// fmt.Printf("Trying device: %v\n", device.Name)
	handle, err := pcap.OpenLive(device.Name, snapshot_len, true, timeout)
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
					outChan <- handle
					return
				}
			}

		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func main() {
	mockingPackets := true

	var handle gopacket.PacketDataSource
	var w io.Writer

	if mockingPackets {
		f, _ := os.Open("./tmp/file.pcap")
		defer f.Close()
		handle, _ = pcapgo.NewReader(f)
	} else {
		handle := FindROTMGDevice()
		defer handle.Close()
	}

	if mockingPackets {
		w = io.Discard
	} else {
		w, _ := os.Create("./tmp/file.pcap")
		defer w.Close()
	}
	packetWriter := pcapgo.NewWriter(w)
	packetWriter.WriteFileHeader(65536, layers.LinkTypeEthernet)

	var ethLayer layers.Ethernet
	var ipv4Layer layers.IPv4
	var tcpLayer layers.TCP
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ipv4Layer,
		&tcpLayer,
	)
	packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)

	for packet := range packetSource.Packets() {
		fmt.Printf("%+v\n", packet)
		if err := packetWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			fmt.Printf("Error writing packet to file: %v\n", err)
		}

		var foundLayerTypes []gopacket.LayerType
		if err := parser.DecodeLayers(packet.Data(), &foundLayerTypes); err != nil {
			fmt.Printf("Trouble decoding layers: %v\n", err)
		}

		for _, layerType := range foundLayerTypes {
			if layerType == layers.LayerTypeTCP && (uint16(tcpLayer.SrcPort) == ROTMGPort || uint16(tcpLayer.DstPort) == ROTMGPort) {
				fmt.Println("TCP Port: ", tcpLayer.SrcPort, "->", tcpLayer.DstPort)
				// fmt.Println(packet.TransportLayer().LayerContents())
			}
		}
	}
}
