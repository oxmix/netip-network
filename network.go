package main

import (
	"errors"
	"github.com/gorilla/websocket"
	"log"
	"netip-network/collector"
	"os"
	"os/signal"
	"time"
)

type connectResponse struct {
	responseBase
	Blackhole bool `json:"blackhole"`
}

type connectPayload struct {
	payloadBase
	FirewallGroups string `json:"firewallGroups"`
}

func main() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	destroy := make(chan bool, 1)

	api := connect(&connectPayload{
		payloadBase: payloadBase{
			Service: "network",
		},
		FirewallGroups: os.Getenv("FIREWALL_GROUPS"),
	})

	col := collector.New()

	fw := NewFirewall()
	fw.SetChanBHCounter(col.ChanBHCounter)
	if api.Blackhole {
		fw.BlackHoleEnable()
		fw.BlackHoleRestore()
	} else {
		fw.BlackHoleDestroy()
	}

	wg := NewWireguard()
	proxy := NewProxies()
	spnDns := NewSpnDns()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	// reader from nodes-handler
	go func() {
		for {
			if wsConnect == nil {
				time.Sleep(time.Second)
				continue
			}

			var res struct {
				Command     string                 `json:"command"`
				Rules       []FirewallRules        `json:"rules"`
				IP          string                 `json:"ip"`
				Wireguards  map[int]WireguardsData `json:"wireguards"`
				WireguardId int                    `json:"wireguardId"`
				Proxies     map[int]ProxiesData    `json:"proxies"`
				ProxyId     int                    `json:"proxyId"`
				SpnDns      *SpnDnsBundle          `json:"spnDns"`
			}
			// ReadMessage needs for ping-pong
			err := wsConnect.ReadJSON(&res)
			if err != nil {
				if !websocket.IsCloseError(err, 1006) {
					log.Println("ws read err:", err)
				}
				time.Sleep(time.Second)
				continue
			}

			// debug
			// log.Println("received command:", res.Command)

			switch res.Command {
			case "services-destroy":
				destroy <- true
				return

			case "firewall-refresh":
				fw.Refresh(res.Rules)
			case "firewall-disable":
				fw.Disable()
			case "blackhole-enable":
				fw.BlackHoleEnable()
			case "blackhole-disable":
				fw.BlackHoleDisable()
			case "blackhole-add":
				fw.BlackHoleExec("add", res.IP)
			case "blackhole-del":
				fw.BlackHoleExec("del", res.IP)

			case "wireguard-refresh":
				wg.Refresh(res.Wireguards)
			case "wireguard-destroy":
				wg.Destroy(res.WireguardId)
			case "wireguard-shared-refresh":
			case "wireguard-n2n-refresh":
				wg.NodeClientRefresh(res.Wireguards)

			case "proxy-refresh":
				proxy.Refresh(res.Proxies)
			case "proxy-destroy":
				proxy.Destroy(res.ProxyId)

			case "spn-dns-refresh":
				spnDns.Refresh(res.SpnDns)
			case "spn-dns-destroy":
				spnDns.Destroy()
			}
		}
	}()

	log.Println("ready to work")

	// writer to nodes-handler
	for {
		select {
		case <-destroy:
			fw.BlackHoleDisable()
			fw.Disable()
			log.Println("service destroyed")
			log.Println("------")
			log.Println("below remains to execution manually:")
			log.Println("# docker rm -f netip.network")
			log.Println("------")
			_ = wsConnect.Close()
			<-destroy

		// ticker-sender stats network
		case <-ticker.C:
			if wsConnect == nil {
				continue
			}
			j := struct {
				Event          string                   `json:"event"`
				CollectNetwork collector.CollectNetwork `json:"collectNetwork"`
			}{
				Event:          "collect-network",
				CollectNetwork: col.Get(),
			}
			err := wsConnect.WriteJSON(j)
			if err != nil {
				// ! lock this select before established connection
				connectDegrade(errors.New("ticker write err: " + err.Error()))
				continue
			}

		// chan-sender stats blackhole counters
		case bhc, ok := <-col.ChanBHCounter:
			if wsConnect == nil || !ok {
				continue
			}
			j := &struct {
				Event            string                      `json:"event"`
				BlackholeCounter *collector.BlackholeCounter `json:"blackholeCounter"`
			}{
				Event:            "blackhole-counter",
				BlackholeCounter: bhc,
			}
			err := wsConnect.WriteJSON(j)
			if err != nil {
				log.Println("who bh counter write err:", err)
				continue
			}

		// chan-sender stats wireguard
		case wgs, ok := <-col.ChanWgStats:
			if wsConnect == nil || !ok {
				continue
			}
			j := &struct {
				Event          string                    `json:"event"`
				WireguardStats *collector.WireguardStats `json:"wireguardStats"`
			}{
				Event:          "wireguard-stats",
				WireguardStats: wgs,
			}
			err := wsConnect.WriteJSON(j)
			if err != nil {
				log.Println("write err:", err)
				continue
			}

		// chan-sender net-sysctl
		case nsc, ok := <-col.ChanNetSysctl:
			if wsConnect == nil || !ok {
				continue
			}
			j := &struct {
				Event     string            `json:"event"`
				NetSysctl map[string]string `json:"netSysctl"`
			}{
				Event:     "net-sysctl",
				NetSysctl: nsc,
			}
			err := wsConnect.WriteJSON(j)
			if err != nil {
				log.Println("write err:", err)
				continue
			}

		// handler terminate
		case <-interrupt:
			log.Println("interrupt")
			if wsConnect == nil {
				return
			}

			err := wsConnect.WriteMessage(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("write close err:", err)
				return
			}
			err = wsConnect.Close()
			if err != nil {
				log.Println("close conn err:", err)
			}
			return
		}
	}
}
