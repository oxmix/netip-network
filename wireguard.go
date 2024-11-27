package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

type WireguardsData struct {
	PrivateKey string `json:"privateKey"`
	Masquerade bool   `json:"masquerade"`
	Shared     bool   `json:"shared"`
	Address    string `json:"address"`
	Network    string `json:"network"`
	Port       int    `json:"port"`
	Dns        string `json:"dns"`
	Peers      []WireguardPeer
}

type WireguardPeer struct {
	PublicKey  string `json:"publicKey"`
	SharedKey  string `json:"sharedKey"`
	Address    string `json:"address"`
	Endpoint   string `json:"endpoint"`
	AllowedIPs string `json:"allowedIPs"`
}

type Wireguard struct{}

func NewWireguard() *Wireguard {
	return &Wireguard{}
}

func (w *Wireguard) shell(command string) string {
	out, err := exec.Command("sh", "-c", command).CombinedOutput()
	if err != nil {
		log.Println("wireguard shell err:", err, "command:", command)
	}
	return strings.TrimSpace(string(out))
}

func (w *Wireguard) fileConf(wgId int) string {
	return fmt.Sprintf("/tmp/netip-wg%d.conf", wgId)
}

func (w *Wireguard) up(wgId int, masquerade, shared bool, network string) {
	w.shell("wg-quick up " + w.fileConf(wgId))

	if masquerade {
		inf := fmt.Sprintf("netip-wg%d", wgId)
		w.shell("nft add table inet " + inf)
		w.shell("nft add chain inet " + inf + " forward-wg '{ type filter hook forward priority -100; policy accept ; }'")
		w.shell("nft add rule inet " + inf + " forward-wg iifname " + inf + " counter mark set 0x10f01")
		w.shell("nft add rule inet " + inf + " forward-wg oifname " + inf + " counter mark set 0x10f01")
		w.shell("nft add chain inet " + inf + " masquerade-wg '{ type nat hook postrouting priority srcnat; policy accept; }'")

		// block access to private addresses for usual wireguard server
		if !shared {
			w.shell("nft add rule inet " + inf + " masquerade-wg ip saddr " + network +
				" ip daddr != '{ 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16 }' counter masquerade")
			w.shell("nft add rule inet  " + inf + " masquerade-wg ip saddr " + network +
				" ip daddr '{ 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16 }' counter drop")
		}

		w.shell("nft list chain ip filter FORWARD | grep 0x00010f01 >/dev/null 2>&1 ||" +
			" nft add rule ip filter FORWARD mark 0x10f01 accept")
	}
}

// sharedMasquerade flush masquerade-wg and adding access rules
func (w *Wireguard) sharedMasquerade(wgId int, access map[string][]string) {
	inf := fmt.Sprintf("netip-wg%d", wgId)
	w.shell("nft flush chain inet " + inf + " masquerade-wg")

	for address, allowed := range access {
		if len(allowed) == 0 {
			continue
		}
		w.shell("nft add rule inet " + inf + " masquerade-wg ip saddr " + address +
			" ip daddr '{ " + strings.Join(allowed, ", ") + " }' counter masquerade")
	}
}

func (w *Wireguard) down(wgId int) {
	w.shell(fmt.Sprintf("nft delete table inet netip-wg%d", wgId))

	w.shell("wg-quick down " + w.fileConf(wgId))
}

func (w *Wireguard) exists(wgId int) bool {
	_, err := exec.Command("sh", "-c",
		fmt.Sprintf("wg show netip-wg%d", wgId)).CombinedOutput()
	return err == nil
}

func (w *Wireguard) reload(wgId int) {
	// "wg syncconf netip-wg123 <(wg-quick strip /tmp/netip.conf)" - wg-quick leaves left zombie process
	w.shell(fmt.Sprintf("wg-quick strip %s > /tmp/netip-wg%d-reload.conf && "+
		"wg syncconf netip-wg%d /tmp/netip-wg%d-reload.conf && "+
		"rm /tmp/netip-wg%d-reload.conf",
		w.fileConf(wgId), wgId, wgId, wgId, wgId))
}

func (w *Wireguard) Refresh(wgs map[int]WireguardsData) {
	for wgId, e := range wgs {
		conf := strings.Builder{}
		conf.WriteString(fmt.Sprintf(`[Interface]
PrivateKey = %s
DNS = %s
Address = %s
ListenPort = %d
SaveConfig = false
MTU = 1380
`, e.PrivateKey, e.Dns, e.Network, e.Port))
		peers := map[string][]string{}
		for _, p := range e.Peers {
			if len(p.PublicKey) == 0 {
				continue
			}
			peers[p.Address] = strings.Split(p.AllowedIPs, ", ")

			conf.WriteString("\n[Peer]\nPublicKey = " + p.PublicKey)
			if p.SharedKey != "" {
				conf.WriteString("\nPresharedKey = " + p.SharedKey)
			}
			if p.AllowedIPs != "" {
				conf.WriteString("\nAllowedIPs = " + p.Address + "/32, " + p.AllowedIPs)
			} else {
				conf.WriteString("\nAllowedIPs = " + p.Address + "/32")
			}
			conf.WriteString("\nPersistentKeepalive = 23\n")
		}

		err := os.WriteFile(w.fileConf(wgId), []byte(conf.String()), 0600)
		if err != nil {
			log.Println("err wg save conf, wg id:", wgId)
			return
		}

		if len(peers) > 0 {
			if w.exists(wgId) {
				w.reload(wgId)
			} else {
				w.up(wgId, e.Masquerade, e.Shared, e.Network)
			}
			if e.Shared {
				w.sharedMasquerade(wgId, peers)
			}
		} else if w.exists(wgId) {
			w.down(wgId)
		}
	}
}

func (w *Wireguard) Destroy(wgId int) {
	if w.exists(wgId) {
		w.down(wgId)
	}
}

func (w *Wireguard) SharedRefresh(wgs map[int]WireguardsData) {
	for wgId, e := range wgs {
		conf := strings.Builder{}
		conf.WriteString(fmt.Sprintf(`[Interface]
PrivateKey = %s
DNS = %s
Address = %s/32
SaveConfig = false
MTU = 1380
`, e.PrivateKey, e.Dns, e.Address))

		quantityPeers := 0
		for _, p := range e.Peers {
			if len(p.PublicKey) == 0 {
				continue
			}
			quantityPeers++
			conf.WriteString(fmt.Sprintf(`
[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s
Endpoint = %s
PersistentKeepalive = 25
`, p.PublicKey, p.SharedKey, p.AllowedIPs, p.Endpoint))
		}
		err := os.WriteFile(w.fileConf(wgId), []byte(conf.String()), 0600)
		if err != nil {
			log.Println("err wg shared save conf, wg id:", wgId)
			return
		}

		if quantityPeers > 0 {
			if w.exists(wgId) {
				w.reload(wgId)
			} else {
				w.up(wgId, e.Masquerade, false, e.Network)
			}
		} else if w.exists(wgId) {
			w.down(wgId)
		}
	}
}
