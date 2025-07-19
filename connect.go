package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	payload   *connectPayload
	wsConnect *websocket.Conn
)

type responseBase struct {
	Ok           bool   `json:"ok"`
	Message      string `json:"message"`
	EndpointIP   string `json:"endpointIP"`
	EndpointPath string `json:"endpointPath"`
	HandshakeKey string `json:"handshakeKey"`
}

type payloadBase struct {
	Hostname string `json:"hostname"`
	Service  string `json:"service"`
}

func connect(cp *connectPayload) *connectResponse {
	if cp != nil {
		payload = cp
	}

	var err error
	payload.Hostname, err = os.Hostname()
	if err != nil {
		return connectFatal(errors.New("hostname err: " + err.Error()))
	}
	plJs, err := json.Marshal(payload)
	if err != nil {
		return connectFatal(errors.New("marshal payload err: " + err.Error()))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	endpoint := os.Getenv("ENDPOINT")
	if endpoint == "" {
		endpoint = "https://oxmix.net/api"
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		endpoint+"/nodes/handshake/v2", bytes.NewReader(plJs))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Key", os.Getenv("CONNECT_KEY"))
	req.Header.Set("X-Version", os.Getenv("VERSION"))
	req.Header.Set("X-Version-Hash", os.Getenv("VERSION_HASH"))
	if err != nil {
		return connectFatal(err)
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	res, err := client.Do(req)
	if err != nil {
		return connectFatal(err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(res.Body)

	if res.StatusCode >= 500 {
		return connectFatal(fmt.Errorf("response status: %s", res.Status))
	}

	api := new(connectResponse)
	err = json.NewDecoder(res.Body).Decode(api)
	if err != nil {
		return connectFatal(errors.New("decode json: " + err.Error()))
	}
	if !api.Ok {
		return connectFatal(errors.New("api message: " + api.Message))
	}

	if api.EndpointIP == "" {
		// usual connect
		wsConnect, _, err = websocket.DefaultDialer.DialContext(ctx, api.EndpointPath, nil)
		if err != nil {
			return connectDegrade(errors.New("dial native: " + err.Error()))
		}
	} else {
		// connect with replace ip
		dialer := websocket.Dialer{
			Proxy: http.ProxyFromEnvironment,
			NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					log.Println("err parse addr dial")
				} else {
					addr = api.EndpointIP + ":" + port
				}
				netDialer := &net.Dialer{}
				return netDialer.DialContext(ctx, network, addr)
			},
		}

		wsConnect, _, err = dialer.DialContext(ctx, api.EndpointPath, nil)
		if err != nil {
			return connectDegrade(errors.New("dial modified: " + err.Error()))
		}
	}

	err = wsConnect.WriteJSON(struct {
		Event   string `json:"event"`
		Key     string `json:"key"`
		Service string `json:"service"`
	}{
		"handshake",
		api.HandshakeKey,
		payload.Service,
	})
	if err != nil {
		return connectDegrade(errors.New("handshake: " + err.Error()))
	}
	for {
		_, _, err = wsConnect.ReadMessage()
		if err != nil {
			return connectDegrade(errors.New("handshake: " + err.Error()))
		}

		log.Println("handshake successful")
		return api
	}
}

func connectFatal(err error) *connectResponse {
	log.Println("handshake request err:", err)
	time.Sleep(5 * time.Second)
	os.Exit(1)
	return nil
}

func connectDegrade(err error) *connectResponse {
	if wsConnect != nil {
		_ = wsConnect.Close()
	}
	wsConnect = nil
	log.Printf("connection failure, err: %s", err.Error())
	if strings.Contains(err.Error(), "number of nodes has been reached") {
		log.Println("trying to reconnect after waiting 5 min.")
		time.Sleep(5 * time.Minute)
	} else {
		log.Println("trying to reconnect after waiting 5 sec.")
		time.Sleep(5 * time.Second)
	}
	return connect(nil)
}
