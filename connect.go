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
	"sync/atomic"
	"time"
)

type ResponseBase struct {
	Ok           bool   `json:"ok"`
	Message      string `json:"message"`
	EndpointIP   string `json:"endpointIP"`
	EndpointPath string `json:"endpointPath"`
	HandshakeKey string `json:"handshakeKey"`
}

type PayloadBase struct {
	Hostname string `json:"hostname"`
	Service  string `json:"service"`
}

type Connection struct {
	alive     atomic.Bool
	reconnect chan struct{}
	client    *http.Client
	ws        *websocket.Conn
	payload   *ConnectPayload
	response  *ConnectResponse
}

func NewConnection(cp *ConnectPayload) *Connection {
	c := &Connection{
		reconnect: make(chan struct{}),
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: 6 * time.Second,
				}).DialContext,
				MaxIdleConns:    100,
				IdleConnTimeout: 60 * time.Second,
			},
			Timeout: 8 * time.Second,
		},
		payload: cp,
	}
	log.Println("[connect] started")
	for {
		err := c.connect()
		if err != nil {
			c.degrade(err, false)
			continue
		}
		break
	}
	go c.maintain()
	return c
}

func (c *Connection) Response() *ConnectResponse {
	return c.response
}

func (c *Connection) Alive() bool {
	return c.alive.Load()
}

func (c *Connection) maintain() {
	log.Println("[connect] maintenance")
	for range c.reconnect {
		log.Println("[connect] reconnection")
		err := c.connect()
		if err != nil {
			c.degrade(err, true)
		}
	}
}

func (c *Connection) connect() error {
	var err error
	c.payload.Hostname, err = os.Hostname()
	if err != nil {
		c.fatal(errors.New("hostname err: " + err.Error()))
	}
	plJs, err := json.Marshal(c.payload)
	if err != nil {
		c.fatal(errors.New("marshal payload err: " + err.Error()))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 16*time.Second)
	defer cancel()

	endpoint := os.Getenv("ENDPOINT")
	if endpoint == "" {
		endpoint = "https://cloudnetip.com/api"
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		endpoint+"/nodes/handshake/v2", bytes.NewReader(plJs))
	if err != nil {
		c.fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Key", os.Getenv("CONNECT_KEY"))
	req.Header.Set("X-Version", os.Getenv("VERSION"))
	req.Header.Set("X-Version-Hash", os.Getenv("VERSION_HASH"))
	res, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(res.Body)

	if res.StatusCode >= 500 {
		return fmt.Errorf("response status: %s", res.Status)
	}

	c.response = new(ConnectResponse)
	err = json.NewDecoder(res.Body).Decode(c.response)
	if err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	if !c.response.Ok {
		return errors.New("api message: " + c.response.Message)
	}

	if c.response.EndpointIP == "" {
		// usual connect
		c.ws, _, err = websocket.DefaultDialer.DialContext(ctx, c.response.EndpointPath, nil)
		if err != nil {
			return fmt.Errorf("dial native: %w", err)
		}
	} else {
		// connect with replace ip
		dialer := websocket.Dialer{
			Proxy: http.ProxyFromEnvironment,
			NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					log.Println("[connect] parse addr dial, err:", err)
				} else {
					addr = c.response.EndpointIP + ":" + port
				}
				netDialer := &net.Dialer{}
				return netDialer.DialContext(ctx, network, addr)
			},
		}

		c.ws, _, err = dialer.DialContext(ctx, c.response.EndpointPath, nil)
		if err != nil {
			return fmt.Errorf("dial modified: %w", err)
		}
	}

	err = c.ws.WriteJSON(struct {
		Event   string `json:"event"`
		Key     string `json:"key"`
		Service string `json:"service"`
	}{
		"handshake",
		c.response.HandshakeKey,
		c.payload.Service,
	})
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	for {
		_, _, err = c.ws.ReadMessage()
		if err != nil {
			return fmt.Errorf("handshake: %w", err)
		}
		log.Println("[connect] handshake successful")
		break
	}

	c.alive.Store(true)
	return nil
}

func (c *Connection) Write(v any, note string) {
	if !c.Alive() {
		return
	}

	wErr := c.ws.WriteJSON(v)
	if wErr != nil {
		// lock before established connection
		c.degrade(fmt.Errorf("%s: %w", note, wErr), true)
	}
}

func (c *Connection) SendClose() {
	if !c.Alive() {
		return
	}
	c.alive.Store(false)

	err := c.ws.WriteMessage(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if err != nil {
		log.Println("[connect] write close err:", err)
		return
	}
	err = c.ws.Close()
	if err != nil {
		log.Println("[connect] close conn err:", err)
	}
}

func (c *Connection) fatal(err error) {
	c.alive.Store(false)
	log.Println("[connect] fatal: shutting down in 5 seconds, handshake request err:", err)
	time.Sleep(5 * time.Second)
	os.Exit(1)
}

func (c *Connection) degrade(err error, reconnect bool) {
	c.alive.Store(false)
	if c.ws != nil {
		_ = c.ws.Close()
	}
	log.Println("[connect] failure, err:", err)
	if err != nil {
		if strings.Contains(err.Error(), "number of nodes has been reached") {
			log.Println("[connect] trying to reconnect after waiting 5 minutes")
			time.Sleep(5 * time.Minute)
		} else {
			log.Println("[connect] trying to reconnect after waiting 5 seconds")
			time.Sleep(5 * time.Second)
		}
	}
	if reconnect {
		go func() { c.reconnect <- struct{}{} }()
	}
}
