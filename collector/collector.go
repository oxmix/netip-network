package collector

import (
	"sync"
	"time"
)

type CollectNetwork struct {
	Time               time.Time
	NetworkStats       map[string]NetworkStats `json:"networkStats"`
	SocketStats        map[string]int          `json:"socketStats"`
	NetfilterConnTrack int                     `json:"netfilterConnTrack"`
}

type NetworkStats struct {
	BytesRx   int `json:"bytesRx"`
	PacketsRx int `json:"packetsRx"`
	BytesTx   int `json:"bytesTx"`
	PacketsTx int `json:"packetsTx"`
}

type BlackholeCounter struct {
	QuantityRules int `json:"quantityRules"`
	IPv4          struct {
		Packets int `json:"packets"`
		Bytes   int `json:"bytes"`
	}
	IPv6 struct {
		Packets int `json:"packets"`
		Bytes   int `json:"bytes"`
	}
}

type WireguardStats struct {
	WgId            uint   `json:"wgId"`
	Peer            string `json:"peer"`
	LatestHandshake int64  `json:"latestHandshake"`
	BytesRx         uint   `json:"bytesRx"`
	BytesTx         uint   `json:"bytesTx"`
}

type Collector struct {
	mu   sync.Mutex
	data CollectNetwork

	ChanBHCounter chan *BlackholeCounter
	prevWgStats   map[string]*WireguardStats
	ChanWgStats   chan *WireguardStats
	ChanNetSysctl chan map[string]string
}

func New() *Collector {
	c := &Collector{
		mu:            sync.Mutex{},
		data:          CollectNetwork{},
		ChanBHCounter: make(chan *BlackholeCounter, 1),
		prevWgStats:   map[string]*WireguardStats{},
		ChanWgStats:   make(chan *WireguardStats, 1),
		ChanNetSysctl: make(chan map[string]string, 1),
	}

	go c.collectNetwork()
	go c.collectWireguard()
	go c.collectSysctl()
	go c.collectSysctlHourly()

	return c
}

func (c *Collector) Get() CollectNetwork {
	return c.data
}
