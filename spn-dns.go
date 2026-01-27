package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

const dnsConfFile = "/tmp/netip-spn-dns"

var preDnsHosts = ""
var preDnsForward = ""

type SpnDnsBundle struct {
	WgId    int          `json:"wgId"`
	Forward []string     `json:"forward"`
	Rules   []SpnDnsRule `json:"rules"`
}

type SpnDnsRule struct {
	IP   string `json:"ip"`
	Host string `json:"host"`
}

type SpnDns struct{}

func NewSpnDns() *SpnDns {
	return &SpnDns{}
}

func (d *SpnDns) shell(command string, errIgnore bool) string {
	out, err := exec.Command("sh", "-c", command).CombinedOutput()
	if err != nil && !errIgnore {
		log.Println("[spn] dns shell err:", err, "command:", command)
	}
	return strings.TrimSpace(string(out))
}

func (d *SpnDns) up() {
	go func() {
		log.Println("[spn] dns up")
		d.shell("/coredns -conf "+dnsConfFile+" > /var/log/spn-dns.log 2>&1", false)
	}()
}

func (d *SpnDns) down() {
	log.Println("[spn] dns down")
	d.shell("pkill coredns", true)
	err := os.Remove(dnsConfFile)
	if err != nil && !os.IsNotExist(err) {
		log.Println("[spn] dns clean conf err:", err)
	}
}

func (d *SpnDns) Refresh(bundle *SpnDnsBundle) {
	if len(bundle.Forward) == 0 || len(bundle.Rules) == 0 {
		d.down()
		return
	}

	forward := strings.Join(bundle.Forward, " ")
	hosts := ""
	for _, e := range bundle.Rules {
		hosts += fmt.Sprintf("\n\t\t%s %s", e.IP, e.Host)
	}

	// if the rules have not changed
	if preDnsHosts == hosts && preDnsForward == forward {
		return
	}
	d.down()
	preDnsHosts = hosts
	preDnsForward = forward

	conf := fmt.Sprintf(`.:53 {
	bind netip-wg%d
	hosts {%s
		fallthrough
	}
	forward . %s
	cache 60
	#log
	errors
}`, bundle.WgId, hosts, forward)

	err := os.WriteFile(dnsConfFile, []byte(conf), 0644)
	if err != nil {
		log.Println("[spn] dns save conf, err:", err)
		return
	}
	d.up()
}

func (d *SpnDns) Destroy() {
	d.down()
}
