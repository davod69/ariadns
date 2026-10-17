package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ariadns/internal/config"
)

const installURL = "https://raw.githubusercontent.com/davod69/ariadns/main/scripts/install.sh"

type ctl struct {
	base, token string
	in          *bufio.Reader
}

func (c *ctl) call(method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the ariadns service (is it running?): %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		var e struct{ Error string }
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return fmt.Errorf("%s", e.Error)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *ctl) ask(prompt, def string) string {
	if def != "" {
		prompt += " [" + def + "]"
	}
	fmt.Print(prompt + ": ")
	s, _ := c.in.ReadString('\n')
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	return s
}

func fb(n int64) string {
	u := []string{"B", "KB", "MB", "GB", "TB"}
	f, i := float64(n), 0
	for f >= 1024 && i < 4 {
		f /= 1024
		i++
	}
	return strconv.FormatFloat(f, 'f', 1, 64) + " " + u[i]
}

type subView struct {
	ID, Name, IP, Token, Status string
	Limit                       int64 `json:"limit_bytes"`
	Used                        int64 `json:"used_bytes"`
	ExpiresAt                   int64 `json:"expires_at"`
	Enabled                     bool
}

func (c *ctl) subs() ([]subView, error) {
	var l []subView
	return l, c.call("GET", "/api/subs", nil, &l)
}

func (c *ctl) printSubs(l []subView) {
	if len(l) == 0 {
		fmt.Println("  (no subscribers)")
	}
	for i, s := range l {
		exp := "never"
		if s.ExpiresAt != 0 {
			exp = time.Unix(s.ExpiresAt, 0).Format("2006-01-02")
		}
		lim := "unlimited"
		if s.Limit != 0 {
			lim = fb(s.Limit)
		}
		ip := s.IP
		if ip == "" {
			ip = "-"
		}
		fmt.Printf("  %2d) %-16s %-15s %-10s %s / %s  exp %s\n", i+1, s.Name, ip, s.Status, fb(s.Used), lim, exp)
	}
}

func (c *ctl) pick(l []subView) *subView {
	c.printSubs(l)
	if len(l) == 0 {
		return nil
	}
	n, _ := strconv.Atoi(c.ask("Number", ""))
	if n < 1 || n > len(l) {
		fmt.Println("  cancelled")
		return nil
	}
	return &l[n-1]
}

func runMenu(cfgPath string) int {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		return 2
	}
	if cfg.DataDir == "" || cfg.Web.Listen == "" {
		fmt.Fprintln(os.Stderr, "the menu needs data_dir and web.listen in the config")
		return 2
	}
	tok := cfg.Web.Token
	if tok == "" {
		b, err := os.ReadFile(filepath.Join(cfg.DataDir, "ctl.token"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot read control token (run as root):", err)
			return 1
		}
		tok = strings.TrimSpace(string(b))
	}
	c := &ctl{base: "http://" + cfg.Web.Listen, token: tok, in: bufio.NewReader(os.Stdin)}
	for {
		fmt.Print(`
================ ariadns ================
  1) Status and panel address
  2) List subscribers
  3) Add subscriber
  4) Delete subscriber
  5) Enable / disable subscriber
  6) Routing categories
  7) Set server public IP
  8) Reset admin password
  9) Restart service
 10) View logs
 11) Update
 12) Uninstall
  0) Exit
`)
		var err error
		switch c.ask("Choose", "") {
		case "1":
			err = c.status()
		case "2":
			var l []subView
			if l, err = c.subs(); err == nil {
				c.printSubs(l)
			}
		case "3":
			err = c.add()
		case "4":
			err = c.del()
		case "5":
			err = c.toggle()
		case "6":
			err = c.categories()
		case "7":
			ip := c.ask("Public IPv4", "")
			err = c.call("PUT", "/api/smart", map[string]any{"public_ip": ip}, nil)
		case "8":
			var r struct{ Password string }
			if err = c.call("POST", "/api/admin/password", map[string]any{"reset": true}, &r); err == nil {
				fmt.Println("  New admin password (shown once):", r.Password)
			}
		case "9":
			err = sh("systemctl restart ariadns && systemctl is-active ariadns")
		case "10":
			err = sh("journalctl -u ariadns -n 50 --no-pager")
		case "11":
			err = sh("curl -fsSL " + installURL + " | bash")
		case "12":
			if strings.EqualFold(c.ask("Really uninstall? (yes/no)", "no"), "yes") {
				return mustExit(sh("curl -fsSL " + installURL + " | ARIADNS_UNINSTALL=1 bash"))
			}
		case "0", "q", "":
			return 0
		default:
			fmt.Println("  unknown choice")
		}
		if err != nil {
			fmt.Println("  error:", err)
		}
	}
}

func mustExit(err error) int {
	if err != nil {
		fmt.Println("error:", err)
		return 1
	}
	return 0
}

func sh(cmd string) error {
	x := exec.Command("bash", "-c", cmd)
	x.Stdin, x.Stdout, x.Stderr = os.Stdin, os.Stdout, os.Stderr
	return x.Run()
}

func (c *ctl) status() error {
	var o struct {
		Version     string
		Subscribers int
		PublicIP    string `json:"public_ip"`
		Relay       map[string]uint64
		Stats       struct{ Total uint64 }
	}
	if err := c.call("GET", "/api/overview", nil, &o); err != nil {
		return err
	}
	var info struct{ URL string }
	_ = c.call("GET", "/api/admin/info", nil, &info)
	fmt.Printf("  version      %s\n  DNS queries  %d\n  subscribers  %d\n  public IP    %s\n", o.Version, o.Stats.Total, o.Subscribers, orDash(o.PublicIP))
	if o.Relay != nil {
		fmt.Printf("  relay        %d connections, %d rejected\n", o.Relay["relayed"], o.Relay["rejected"])
	}
	fmt.Println("  panel        ", info.URL)
	fmt.Println("  (the password is not stored in readable form; use option 8 to reset it)")
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "not set (use option 7)"
	}
	return s
}

func (c *ctl) add() error {
	name := c.ask("Name", "")
	ip := c.ask("Client IP (empty = user activates via portal link)", "")
	gb, _ := strconv.ParseFloat(c.ask("Traffic limit in GB (0 = unlimited)", "0"), 64)
	days, _ := strconv.Atoi(c.ask("Days valid (0 = never expires)", "30"))
	var v subView
	err := c.call("POST", "/api/subs", map[string]any{"name": name, "ip": ip, "limit_gb": gb, "days": days, "self_rebind": true}, &v)
	if err != nil {
		return err
	}
	var info struct{ URL string }
	_ = c.call("GET", "/api/admin/info", nil, &info)
	portal := info.URL
	if i := strings.Index(portal, "://"); i >= 0 {
		if j := strings.Index(portal[i+3:], "/"); j >= 0 {
			portal = portal[:i+3+j]
		}
	}
	fmt.Println("  created. Portal link for the user:")
	fmt.Printf("  %s/sub/%s\n", portal, v.Token)
	return nil
}

func (c *ctl) del() error {
	l, err := c.subs()
	if err != nil {
		return err
	}
	s := c.pick(l)
	if s == nil {
		return nil
	}
	if !strings.EqualFold(c.ask("Delete "+s.Name+"? (yes/no)", "no"), "yes") {
		return nil
	}
	return c.call("DELETE", "/api/subs/"+s.ID, nil, nil)
}

func (c *ctl) toggle() error {
	l, err := c.subs()
	if err != nil {
		return err
	}
	s := c.pick(l)
	if s == nil {
		return nil
	}
	return c.call("PATCH", "/api/subs/"+s.ID, map[string]any{"enabled": !s.Enabled}, nil)
}

func (c *ctl) categories() error {
	var sn struct {
		Categories []struct {
			ID, Title string
			Enabled   bool
			Domains   int
		}
	}
	if err := c.call("GET", "/api/smart", nil, &sn); err != nil {
		return err
	}
	for i, k := range sn.Categories {
		mark := " "
		if k.Enabled {
			mark = "x"
		}
		fmt.Printf("  %2d) [%s] %s (%d domains)\n", i+1, mark, k.Title, k.Domains)
	}
	n, _ := strconv.Atoi(c.ask("Number to toggle (empty = back)", ""))
	if n < 1 || n > len(sn.Categories) {
		return nil
	}
	sn.Categories[n-1].Enabled = !sn.Categories[n-1].Enabled
	var on []string
	for _, k := range sn.Categories {
		if k.Enabled {
			on = append(on, k.ID)
		}
	}
	if on == nil {
		on = []string{}
	}
	return c.call("PUT", "/api/smart", map[string]any{"enabled": on}, nil)
}
