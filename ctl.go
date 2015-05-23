package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"gopkg.in/logex.v1"
)

type IPStype int

const (
	IP_ROUTE IPStype = iota
	IP_OPENVPN
	IP_PPP_UP
	IP_PPP_DOWN
)

type Flag struct {
	VpnConf string
	IpRule  string
	IpDown  string
	IpUp    string

	PingHost string
	PPPName  string
}

func NewFlag() *Flag {
	f := new(Flag)
	flag.StringVar(&f.VpnConf, "v", "/etc/openvpn/server.conf", "conf file path")
	flag.StringVar(&f.IpRule, "i", "/etc/openvpn/ip.rule", "ip rule file path")
	flag.StringVar(&f.IpUp, "up", "/etc/ppp/ip-up.d/openvpn", "ip up file path")
	flag.StringVar(&f.IpDown, "dn", "/etc/ppp/ip-down.d/openvpn", "ip down file path")
	flag.StringVar(&f.PPPName, "n", "", "pppd profile name")
	flag.StringVar(&f.PingHost, "test", "173.252.120.6:80", "which host to test connected!")
	flag.Parse()
	return f
}

type IpLine struct {
	IP    []string // 127.0.0.1
	IPStr string
	Mask  int // 24
}

func (i IpLine) EqualIP(i2 IpLine) bool {
	return i.IPStr == i2.IPStr
}

func (i IpLine) Equal(i2 IpLine) bool {
	return i.EqualIP(i2) && i.Mask == i2.Mask
}

func (i IpLine) BindCmd() string {
	return fmt.Sprintf("/sbin/route add %s dev ppp0", i.RouteString(true))
}

func (i IpLine) Bind() error {
	return exec.Command("bash", "-c", i.BindCmd()).Run()
}

func (i IpLine) UnbindCmd() string {
	return fmt.Sprintf("/sbin/route delete %s", i.RouteString(true))
}

func (i IpLine) Unbind() error {
	return exec.Command("bash", "-c", i.UnbindCmd()).Run()
}

func (i IpLine) RouteString(net bool) string {
	ip, _ := i.MaskIp()
	data := ip + "/" + strconv.Itoa(i.Mask)
	if net && i.Mask != 32 {
		data = "-net " + data
	}
	return data
}

func (l IpLine) MaskIpString() string {
	ip, mask := l.MaskIp()
	return ip + " " + mask
}

func (l IpLine) MaskIp() (string, string) {
	// simple do
	var data []string
	var ip []string
	for i := 0; i < 32; i += 8 {
		if i+8 <= l.Mask {
			ip = append(ip, l.IP[i/8])
			data = append(data, "255")
		} else {
			ip = append(ip, "0")
			data = append(data, "0")
		}
	}

	return strings.Join(ip, "."), strings.Join(data, ".")
}

func NewIpLine(data []byte) (l IpLine, err error) {
	if data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}

	mask := ""
	// mask
	if idx := bytes.Index(data, []byte{'/'}); idx < 0 {
		mask = "32"
	} else {
		mask = string(data[idx+1:])
		data = data[:idx]
	}

	if l.Mask, err = strconv.Atoi(mask); err != nil || l.Mask > 32 || l.Mask < 0 {
		err = logex.NewError("parse mask fail:", l.Mask)
		return
	}

	ip := net.ParseIP(string(data))
	if ip == nil {
		err = logex.NewError("invalid ip: %s", string(data))
		return
	}

	for m := l.Mask / 8; m < 4; m++ {
		a := len(ip) - 4 + m
		ip[a] = 0
	}

	l.IPStr = ip.String()
	l.IP = strings.Split(l.IPStr, ".")
	return
}

type IpLines []IpLine

func NewIpLines() IpLines {
	ip := make(IpLines, 0)
	return ip
}

func (l *IpLines) Append(i IpLine) {
	*l = append(*l, i)
}

func (ls IpLines) FindIP(i IpLine) int {
	for idx, l := range ls {
		if l.EqualIP(i) {
			return idx
		}
	}
	return -1
}

func (ls IpLines) Get(idx int) IpLine {
	return ls[idx]
}

func (ls *IpLines) Add(i IpLine) error {
reAdd:
	idx := ls.FindIP(i)
	if idx < 0 {
		i.Bind()
		ls.Append(i)
		return nil
	}
	oldIP := ls.Get(idx)
	if oldIP.Equal(i) {
		return logex.NewError("exist!")
	}

	ls.DeleteByIP(oldIP)
	goto reAdd
}

func (ls *IpLines) DeleteByIP(i IpLine) bool {
	idx := ls.FindIP(i)
	if idx < 0 {
		return false
	}
	if err := ls.Get(idx).Unbind(); err != nil {
		logex.Error(err)
	}
	*ls = append((*ls)[:idx], (*ls)[idx+1:]...)
	return true
}

func (l IpLines) DumpRuleToFile(filePath string, prefix []byte, ipStyle IPStype) error {
	var f *os.File
	var err error
	switch ipStyle {
	case IP_PPP_DOWN, IP_PPP_UP:
		f, err = os.OpenFile(filePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.ModePerm)
	default:
		f, err = os.Create(filePath)
	}
	if err != nil {
		return logex.Trace(err)
	}
	defer f.Close()

	if prefix != nil {
		_, err = f.Write(prefix)
		if err != nil {
			return logex.Trace(err)
		}
	}

	for _, il := range l {
		ip := ""
		switch ipStyle {
		case IP_ROUTE:
			ip = il.RouteString(false)
		case IP_OPENVPN:
			ip = fmt.Sprintf(`push "route %s"`, il.MaskIpString())
		case IP_PPP_UP:
			ip = il.BindCmd()
		case IP_PPP_DOWN:
			ip = il.UnbindCmd()
		}
		io.WriteString(f, ip+"\n")
	}
	return nil
}

func (l *IpLines) AppendsByFile(file string) error {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return logex.Trace(err)
	}
	r := bytes.NewBuffer(data)

	for err == nil {
		data, err = r.ReadBytes('\n')
		if err != nil {
			err = logex.Trace(err)
			continue
		}
		ip, err := NewIpLine(data)
		if err != nil {
			logex.Error("parse ipline error:", err, ",ignore...")
			continue
		}
		l.Add(ip)
	}
	return nil
}

func (f *Flag) ReadConf() ([]byte, error) {
	data, err := ioutil.ReadFile(f.VpnConf)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// p-to-p protocol
type PPP struct {
	ProfName string
}

func (p *PPP) Connect() error {
	logex.Error("try to connect ppp")
	return exec.Command("pppd", "call", p.ProfName).Run()
}

func (p *PPP) Kill() error {
	cmd := fmt.Sprintf("ps aux|grep -v grep|grep -v '%s'|grep 'pppd call'|awk '{print $2}'|xargs kill",
		os.Args[0],
	)
	_, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	logex.Error("try to kill ppp")
	return err
}

func (p *PPP) Reconnect(force bool) error {
	if err := p.Kill(); err != nil {
		logex.Error("kill error:", err)
		if !force {
			return err
		}
	}
	return p.Connect()
}

func CheckHost(host string, ppp *PPP, ipList IpLines) {
	for _ = range time.Tick(30 * time.Second) {
		conn, err := net.DialTimeout("tcp", host, 5*time.Second)
		if conn != nil {
			conn.Close()
		}
		if err != nil {
			logex.Error("connect to ", host, " error:", err)
			ppp.Reconnect(true)
			EnsureRouter(ipList)
		}
	}
}

func EnsureRouter(ipList IpLines) []string {
	ret := []string{}
	for _, l := range ipList {
		if err := l.Bind(); err != nil {
			ret = append(ret, l.BindCmd()+":"+err.Error())
		}
	}
	return ret
}

func main() {
	f := NewFlag()
	confData, err := f.ReadConf()
	if err != nil {
		logex.Fatal(err)
	}
	reader := bytes.NewBuffer(confData)

	var readFile []byte
	var line []byte
	for err == nil {
		line, err = reader.ReadBytes('\n')
		if err != nil {
			continue
		}

		readFile = append(readFile, line...)
		if bytes.Equal(line, []byte("#route\n")) {
			break
		}
	}

	ipList := NewIpLines()

	if err := ipList.AppendsByFile(f.IpRule); err != nil {
		logex.Fatal(err)
	}

	execHeader := []byte("#!/bin/bash\n")

	funcDump := func() {
		ipList.DumpRuleToFile(f.IpRule, nil, IP_ROUTE)
		ipList.DumpRuleToFile(f.VpnConf, readFile, IP_OPENVPN)
		ipList.DumpRuleToFile(f.IpUp, execHeader, IP_PPP_UP)
		ipList.DumpRuleToFile(f.IpDown, execHeader, IP_PPP_DOWN)
		//ipList.DumpRuleToFile((filePath string, prefix []byte, ipStyle IPStype))
	}

	ppp := &PPP{f.PPPName}

	go func() {
		CheckHost(f.PingHost, ppp, ipList)
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/list", func(w http.ResponseWriter, req *http.Request) {
		for _, l := range ipList {
			w.Write([]byte(l.RouteString(false) + "\n"))
		}
	})
	mux.HandleFunc("/ensure_router", func(w http.ResponseWriter, req *http.Request) {
		EnsureRouter(ipList)
	})
	mux.HandleFunc("/debug", func(w http.ResponseWriter, req *http.Request) {
		b, _ := json.MarshalIndent(ipList, "", "\t")
		w.Write(b)
		w.Write([]byte("\n"))
	})
	mux.HandleFunc("/del", func(w http.ResponseWriter, req *http.Request) {
		query := req.URL.Query()
		ip := query.Get("d")
		il, err := NewIpLine([]byte(ip))
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if ipList.DeleteByIP(il) {
			funcDump()
			io.WriteString(w, "deleted!\n")
		} else {
			io.WriteString(w, "not found!\n")
		}
	})
	mux.HandleFunc("/add", func(w http.ResponseWriter, req *http.Request) {
		query := req.URL.Query()
		ip := query.Get("d")
		il, err := NewIpLine([]byte(ip))
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		err = ipList.Add(il)
		if err == nil {
			funcDump()
			io.WriteString(w, "added!\n")
			return
		}
		logex.Error(err)
		io.WriteString(w, err.Error()+"\n")
	})

	mux.HandleFunc("/restart", func(w http.ResponseWriter, req *http.Request) {
		if err := exec.Command("service", "openvpn", "restart").Run(); err != nil {
			http.Error(w, err.Error(), 500)
		} else {
			io.WriteString(w, "restarted!\n")
		}
	})

	mux.HandleFunc("/reppp", func(w http.ResponseWriter, req *http.Request) {
		err := ppp.Reconnect(true)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		io.WriteString(w, "reconnected ppp!\n")
	})

	// 一个要到/etc/ppp/ip-up
	// 另一个要到 /etc/openvpn/server.conf
	logex.Fatal(http.ListenAndServe(":8081", mux))

}
