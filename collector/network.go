package collector

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

var (
	netLoad = map[string]*NetworkStats{}
	netPrev = map[string]*NetworkStats{}
)

func (c *Collector) collectNetwork() {
	for {
		c.data.Time = time.Now().UTC()
		c.netDevHandler("/proc/net/dev")
		c.netSocketHandler()
		time.Sleep(time.Second)
	}
}

func (c *Collector) netDevHandler(file string) {
	netDev, err := os.Open(file)
	if err != nil {
		return
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(netDev)

	defer c.mu.Unlock()
	c.mu.Lock()

	s := bufio.NewScanner(netDev)
	for s.Scan() {
		var (
			face                                                                           string
			bytesRx, packetsRx, errsRx, dropRx, fifoRx, frameRx, compressedRx, multicastRx int
			bytesTx, packetsTx, errsTx, dropTx, fifoTx, collsTx, carrierTx, compressedTx   int
		)

		_, err := fmt.Sscanf(s.Text(),
			"%s %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",
			&face, &bytesRx, &packetsRx, &errsRx, &dropRx, &fifoRx, &frameRx, &compressedRx, &multicastRx,
			&bytesTx, &packetsTx, &errsTx, &dropTx, &fifoTx, &collsTx, &carrierTx, &compressedTx)

		if err != nil {
			continue
		}

		face = strings.TrimSpace(strings.TrimSuffix(face, ":"))

		if (bytesRx == 0 && bytesTx == 0) ||
			strings.HasPrefix(face, "veth") ||
			face == "lo" {
			continue
		}

		if _, ok := netPrev[face]; !ok {
			netPrev[face] = &NetworkStats{}
			netLoad[face] = &NetworkStats{}
		}

		netLoad[face].BytesRx = bytesRx - netPrev[face].BytesRx
		netPrev[face].BytesRx = bytesRx

		netLoad[face].PacketsRx = packetsRx - netPrev[face].PacketsRx
		netPrev[face].PacketsRx = packetsRx

		netLoad[face].BytesTx = bytesTx - netPrev[face].BytesTx
		netPrev[face].BytesTx = bytesTx

		netLoad[face].PacketsTx = packetsTx - netPrev[face].PacketsTx
		netPrev[face].PacketsTx = packetsTx
	}

	c.data.NetworkStats = map[string]NetworkStats{}
	for face, val := range netLoad {
		c.data.NetworkStats[face] = *val
	}
}

func (c *Collector) netSocketHandler() {
	c.data.SocketStats = map[string]int{
		"tcp":  countLines("/proc/net/tcp") - 1,
		"tcp6": countLines("/proc/net/tcp6") - 1,
		"udp":  countLines("/proc/net/udp") - 1,
		"udp6": countLines("/proc/net/udp6") - 1,
	}
}

func countLines(filename string) int {
	file, err := os.Open(filename)
	if err != nil {
		log.Println("open file err:", filename)
		return 0
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Println("close file err:", filename)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
	}

	if err := scanner.Err(); err != nil {
		log.Println("scan file err:", filename)
		return 0
	}

	return lineCount
}
