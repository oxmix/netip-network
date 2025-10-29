package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"netip-network/collector"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type FirewallRules struct {
	Protocol  string `json:"protocol"`
	Source    string `json:"source"`
	Ports     string `json:"ports"`
	Target    string `json:"target"`
	NatOutput bool   `json:"natOutput"`
}

type Firewall struct {
	table             string
	chainOutput       string
	tableBlackhole    string
	blackHole         bool
	blackHoleQuantity int
	blackHoleCounter  chan<- *collector.BlackholeCounter
	blackHoleExists   map[string]struct{}
	bhStatsStopper    chan bool
	bhStatsTicker     *time.Ticker
	bhStatsReg        *regexp.Regexp
}

func NewFirewall() *Firewall {
	return &Firewall{
		table:           "netip",
		chainOutput:     "netip-output",
		tableBlackhole:  "netip-blackhole",
		blackHoleExists: map[string]struct{}{},
		bhStatsStopper:  make(chan bool, 1),
		bhStatsReg:      regexp.MustCompile(`@(.+?) counter packets (\d+) bytes (\d+) drop`),
	}
}

func (f *Firewall) shell(command string) string {
	out, err := exec.Command("sh", "-c", command).CombinedOutput()
	if err != nil {
		log.Println("firewall shell err:", err, "command:", command)
	}
	return strings.TrimSpace(string(out))
}

func (f *Firewall) shellOk(command string) bool {
	command += " >/dev/null 2>&1 && echo yes"
	out, err := exec.Command("sh", "-c", command).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "yes"
}

func (f *Firewall) verIp(ip string) string {
	pip := net.ParseIP(ip)
	if pip != nil && strings.Count(ip, ":") >= 2 {
		return "ip6"
	}
	return "ip"
}

func (f *Firewall) Refresh(rules []FirewallRules) {
	log.Println("refreshing firewall")

	f.shell("nft add table inet " + f.table)
	f.shell("nft add chain inet " + f.table + " input '{ type filter hook input priority 0; policy drop ; }'")
	f.shell("nft flush chain inet " + f.table + " input")
	f.shell("nft add rule inet " + f.table + " input iif lo accept")
	f.shell("nft add rule inet " + f.table + " input iifname docker0 accept")
	f.shell("nft add rule inet " + f.table + " input ct state related,established accept")
	f.shell("nft add rule inet " + f.table + " input ct state invalid counter drop")

	// nat filter
	f.shell("nft add chain ip nat " + f.table)
	f.shell("nft flush chain ip nat " + f.table)
	f.shell("nft add rule ip nat " + f.table + " iifname docker0 counter return")
	existsPre := f.shellOk("nft list chain ip nat PREROUTING | grep -i 'jump " + f.table + "'")
	if !existsPre {
		f.shell("nft insert rule ip nat PREROUTING fib daddr type local counter jump " + f.table)
	}

	// filter rules
	for _, e := range rules {
		protocol := strings.ToLower(e.Protocol)
		target := strings.ToLower(e.Target)

		if protocol == "icmp" {
			source := ""
			if e.Source != "" {
				source = f.verIp(e.Source) + " saddr " + e.Source
			}
			f.shell("nft add rule inet " + f.table + " input " + source +
				" meta l4proto { icmp, ipv6-icmp } counter accept")
			f.shell("nft add rule ip nat " + f.table + " " + source +
				" meta l4proto { icmp, ipv6-icmp } counter return")
			continue
		}

		var (
			proto  = ""
			source = ""
			ports  = ""
		)

		if protocol != "" {
			proto = "meta l4proto " + protocol
		} else if e.Ports != "" {
			proto = "meta l4proto {tcp, udp}"
			protocol = "th"
		}

		if e.Source != "" {
			source = f.verIp(e.Source) + " saddr " + e.Source
		}

		if e.Ports != "" {
			ports = protocol + " dport { " + e.Ports + " }"
		}

		f.shell(fmt.Sprintf(
			"nft add rule inet %s input %s %s %s counter %s",
			f.table, proto, source, ports, target))

		// for containers ports control
		natTarget := "return"
		if target == "drop" {
			natTarget = "drop"
		}
		f.shell(fmt.Sprintf(
			"nft add rule ip nat %s %s %s %s counter %s",
			f.table, proto, source, ports, natTarget))
	}

	f.shell("nft add rule ip nat " + f.table + " counter drop")

	// host nat output, internal requests for spn and n2n ports
	f.shell("nft add chain ip nat " + f.chainOutput)
	f.shell("nft flush chain ip nat " + f.chainOutput)

	existsOut := f.shellOk("nft list chain ip nat OUTPUT | grep -i 'jump " + f.chainOutput + "'")
	if !existsOut {
		f.shell("nft insert rule ip nat OUTPUT ip daddr != 127.0.0.0/8 fib daddr type local counter jump " + f.chainOutput)
	}
	for _, e := range rules {
		if !e.NatOutput || e.Source == "" || e.Ports == "" {
			continue
		}
		f.shell("nft insert rule ip nat " + f.table + "-output ip saddr " +
			e.Source + " tcp dport { " + e.Ports + " } redirect")
	}
}

func (f *Firewall) Disable() {
	log.Println("disabling firewall")

	f.shell("nft add table inet " + f.table)
	f.shell("nft delete table inet " + f.table)

	// rm nat prerouting
	rmPre := f.shell("nft -a list chain ip nat PREROUTING 2> /dev/null | grep -i 'jump " + f.table + "' | head -n 1")
	if rmPre != "" {
		spl := strings.Split(rmPre, " # handle ")
		if len(spl) > 1 {
			f.shell("nft delete rule ip nat PREROUTING handle " + spl[1])
		}
	}
	f.shell("nft flush chain ip nat " + f.table + " 2> /dev/null")
	f.shell("nft delete chain ip nat " + f.table)

	// rm nat output
	rmOut := f.shell("nft -a list chain ip nat OUTPUT 2> /dev/null | grep -i 'jump " + f.chainOutput + "' | head -n 1")
	if rmOut != "" {
		spl := strings.Split(rmOut, " # handle ")
		if len(spl) > 1 {
			f.shell("nft delete rule ip nat OUTPUT handle " + spl[1])
		}
	}
	f.shell("nft flush chain ip nat " + f.chainOutput + " 2> /dev/null")
	f.shell("nft delete chain ip nat " + f.chainOutput)
}

func (f *Firewall) SetChanBHCounter(counter chan<- *collector.BlackholeCounter) {
	f.blackHoleCounter = counter
}

func (f *Firewall) BlackHoleEnable() {
	if f.blackHole {
		return
	}
	f.blackHole = true

	exists := f.shellOk("nft list table inet " + f.tableBlackhole)
	if !exists {
		log.Println("initialing blackhole")

		init := []string{
			"nft add table inet " + f.tableBlackhole,
			"nft add chain inet " + f.tableBlackhole +
				" input '{ type filter hook input priority -200; policy accept ; }'",
			"nft add chain inet " + f.tableBlackhole +
				" forward '{ type filter hook forward priority -200; policy accept ; }'",
			"nft add set inet " + f.tableBlackhole + " IPv4 '{ type ipv4_addr; flags interval; }'",
			"nft add set inet " + f.tableBlackhole + " IPv6 '{ type ipv6_addr; flags interval; }'",
			"nft add rule inet " + f.tableBlackhole + " input ip saddr @IPv4 counter drop",
			"nft add rule inet " + f.tableBlackhole + " input ip6 saddr @IPv6 counter drop",
			"nft add rule inet " + f.tableBlackhole + " forward ip saddr @IPv4 counter drop",
			"nft add rule inet " + f.tableBlackhole + " forward ip6 saddr @IPv6 counter drop",
		}
		for _, i := range init {
			f.shell(i)
		}
	}

	go f.bhStatsCollect()
}

func (f *Firewall) BlackHoleExec(act, ip string) {
	if !f.blackHole {
		return
	}

	set := "IPv4"
	if f.verIp(ip) == "ip6" {
		set = "IPv6"
	}
	if act != "add" {
		act = "delete"
	}
	ok := f.shellOk(fmt.Sprintf("nft %s element inet %s %s '{ %s }'", act, f.tableBlackhole, set, ip))
	if !ok {
		return
	}
	if act == "add" {
		if _, ok := f.blackHoleExists[ip]; !ok {
			f.blackHoleExists[ip] = struct{}{}
			f.blackHoleQuantity++
		}
	}
	if act == "delete" {
		if _, ok := f.blackHoleExists[ip]; ok {
			delete(f.blackHoleExists, ip)
			f.blackHoleQuantity--
		}
	}
}

func (f *Firewall) BlackHoleRestore() {
	log.Println("db restoring of blackhole")

	for _, v := range []int{4, 6} {
		set := f.shell(fmt.Sprintf("nft -j list set inet %s IPv%d", f.tableBlackhole, v))

		var nft struct {
			NFTables []struct {
				Set struct {
					Elem []interface{} `json:"elem"`
				} `json:"set"`
			} `json:"nftables"`
		}

		err := json.Unmarshal([]byte(set), &nft)
		if err != nil {
			continue
		}

		for _, n := range nft.NFTables {
			if len(n.Set.Elem) == 0 {
				continue
			}
			for _, i := range n.Set.Elem {
				if ip, ok := i.(string); ok {
					f.blackHoleQuantity++
					f.blackHoleExists[ip] = struct{}{}
				} else if rn, ok := i.(map[string]any); ok {
					if ip, ok := rn["prefix"].(map[string]any); ok {
						f.blackHoleQuantity++
						f.blackHoleExists[fmt.Sprintf("%s/%0.f", ip["addr"], ip["len"])] = struct{}{}
					}
				}
			}
		}
	}
}

func (f *Firewall) BlackHoleDisable() {
	if !f.blackHole {
		return
	}
	f.blackHole = false
	f.BlackHoleDestroy()
}

func (f *Firewall) BlackHoleDestroy() {
	log.Println("destroying blackhole")

	f.bhStatsStopper <- true
	f.blackHoleQuantity = 0
	f.blackHoleExists = map[string]struct{}{}

	exists := f.shellOk("nft list table inet " + f.tableBlackhole)
	if exists {
		f.shell("nft delete table inet " + f.tableBlackhole)
	}
}

func (f *Firewall) bhStatsCollect() {
	f.bhStatsTicker = time.NewTicker(time.Second / 100)
	defer f.bhStatsTicker.Stop()
	f.bhStatsStopper = make(chan bool, 1)
	for {
		select {
		case <-f.bhStatsTicker.C:
			f.bhStatsTicker.Reset(30 * time.Second)

			ifl := f.shell("nft list chain inet "+f.tableBlackhole+" input") +
				f.shell("nft list chain inet "+f.tableBlackhole+" forward")

			bhc := &collector.BlackholeCounter{
				QuantityRules: f.blackHoleQuantity,
			}
			for _, m := range f.bhStatsReg.FindAllStringSubmatch(ifl, -1) {
				if len(m) < 3 {
					continue
				}
				packets, err := strconv.Atoi(m[2])
				if err != nil {
					packets = 0
				}
				bytes, err := strconv.Atoi(m[3])
				if err != nil {
					bytes = 0
				}
				if m[1] == "IPv4" {
					bhc.IPv4.Packets += packets
					bhc.IPv4.Bytes += bytes
				}
				if m[1] == "IPv6" {
					bhc.IPv6.Packets += packets
					bhc.IPv6.Bytes += bytes
				}
			}

			f.blackHoleCounter <- bhc
		case <-f.bhStatsStopper:
			return
		}
	}
}
