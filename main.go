package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	cG   = "\033[32m"
	cY   = "\033[33m"
	cC   = "\033[36m"
	cB   = "\033[1m"
	cRst = "\033[0m"
)

const banner = `
  ┌────────────────────────────────────────────────────┐
  │  autorecon2  ─  OSCP recon                         │
  │  rustscan → nmap -sV → service goroutines          │
  │  OSCP safe · faster than AutoRecon                 │
  └────────────────────────────────────────────────────┘`

var (
	outDir  string
	verbose bool
	mu      sync.Mutex
)

func pr(col, tag, f string, a ...any) {
	mu.Lock()
	fmt.Printf(col+"["+tag+"]"+cRst+" "+f+"\n", a...)
	mu.Unlock()
}

func info(f string, a ...any) { pr(cC, "*", f, a...) }
func good(f string, a ...any) { pr(cG, "+", f, a...) }
func warn(f string, a ...any) { pr(cY, "!", f, a...) }

func has(p string) bool { _, e := exec.LookPath(p); return e == nil }

func firstFile(pp []string) string {
	for _, p := range pp {
		if _, e := os.Stat(p); e == nil {
			return p
		}
	}
	return ""
}

func firstTool(tt ...string) string {
	for _, t := range tt {
		if has(t) {
			return t
		}
	}
	return ""
}

func mkDir(parts ...string) string {
	d := filepath.Join(parts...)
	os.MkdirAll(d, 0755)
	return d
}

func run(ctx context.Context, outF, prog string, args ...string) error {
	f, err := os.Create(outF)
	if err != nil {
		return err
	}
	defer f.Close()
	cmd := exec.CommandContext(ctx, prog, args...)
	if verbose {
		cmd.Stdout = io.MultiWriter(f, os.Stdout)
		cmd.Stderr = io.MultiWriter(f, os.Stderr)
	} else {
		cmd.Stdout, cmd.Stderr = f, f
	}
	return cmd.Run()
}

// fixSudoPath injects the original user's tool dirs into PATH when running as
// root via sudo, so ~/.local/bin, go/bin and .cargo/bin tools are found.
func fixSudoPath() {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		extra := fmt.Sprintf("/home/%s/.local/bin:/home/%s/go/bin:/home/%s/.cargo/bin",
			sudoUser, sudoUser, sudoUser)
		os.Setenv("PATH", extra+":"+os.Getenv("PATH"))
	}
}

// nmapUDP uses sudo -n (non-interactive) when not root; skips with warning on failure.
func nmapUDP(ctx context.Context, outF string, args ...string) error {
	if os.Getuid() == 0 {
		return run(ctx, outF, "nmap", args...)
	}
	err := run(ctx, outF, "sudo", append([]string{"-n", "nmap"}, args...)...)
	if err != nil {
		warn("UDP scan skipped — needs root (sudo ./autorecon2 or NOPASSWD for nmap)")
	}
	return err
}

// ─────────── PORT PARSERS ────────────────────────────────────────────────

func parseRustscan(s string) []string {
	if m := regexp.MustCompile(`\[([0-9,\s]+)\]`).FindStringSubmatch(s); m != nil {
		var pp []string
		for _, p := range strings.Split(m[1], ",") {
			if p = strings.TrimSpace(p); p != "" {
				pp = append(pp, p)
			}
		}
		return pp
	}
	seen := map[string]bool{}
	var pp []string
	for _, m := range regexp.MustCompile(`Open \S+:(\d+)`).FindAllStringSubmatch(s, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			pp = append(pp, m[1])
		}
	}
	return pp
}

func parseGnmap(f string) []string {
	data, _ := os.ReadFile(f)
	seen := map[string]bool{}
	var pp []string
	for _, m := range regexp.MustCompile(`(\d+)/open/tcp`).FindAllStringSubmatch(string(data), -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			pp = append(pp, m[1])
		}
	}
	sort.Slice(pp, func(i, j int) bool {
		a, _ := strconv.Atoi(pp[i])
		b, _ := strconv.Atoi(pp[j])
		return a < b
	})
	return pp
}

type Port struct {
	Num  int
	Name string
}

func parseServices(gnmap string) []Port {
	data, _ := os.ReadFile(gnmap)
	seen := map[int]bool{}
	var pp []Port
	for _, m := range regexp.MustCompile(`(\d+)/open/tcp//([^/]*)//`).FindAllStringSubmatch(string(data), -1) {
		n, _ := strconv.Atoi(m[1])
		if !seen[n] {
			seen[n] = true
			pp = append(pp, Port{n, strings.TrimSpace(m[2])})
		}
	}
	return pp
}

// ─────────── SERVICE CLASSIFIER ──────────────────────────────────────────

func svcName(p Port) string { return strings.ToLower(p.Name) }

func isHTTP(p Port) bool {
	httpPorts := map[int]bool{
		80: true, 443: true,
		8080: true, 8443: true, 8000: true, 8008: true,
		8888: true, 8844: true,
		9000: true, 9090: true, 9443: true,
		10000: true, // Webmin
		20000: true, // Usermin
		4848: true,  // GlassFish
		8161: true,  // ActiveMQ
		9200: true,  // Elasticsearch
		7070: true, 7443: true,
	}
	return httpPorts[p.Num] ||
		strings.Contains(svcName(p), "http") ||
		strings.Contains(svcName(p), "ssl/http") ||
		strings.Contains(svcName(p), "miniserv") ||
		strings.Contains(svcName(p), "webmin") ||
		strings.Contains(svcName(p), "usermin")
}

func isSMTP(p Port) bool {
	return p.Num == 25 || p.Num == 465 || p.Num == 587 || p.Num == 2525 ||
		strings.Contains(svcName(p), "smtp")
}

// ─────────── WORDLISTS ───────────────────────────────────────────────────

var (
	dirWordlist = []string{
		"/usr/share/seclists/Discovery/Web-Content/common.txt",
		"/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
		"/usr/share/wordlists/dirb/common.txt",
	}
	userWordlist = []string{
		"/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
		"/usr/share/seclists/Usernames/Names/names.txt",
		"/usr/share/wordlists/metasploit/unix_users.txt",
	}
	snmpWordlist = []string{
		"/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt",
	}
)

// ─────────── HTTP ────────────────────────────────────────────────────────

func scanHTTP(ctx context.Context, target string, p Port, base string, wg *sync.WaitGroup) {
	defer wg.Done()

	scheme := "http"
	if p.Num == 443 || p.Num == 8443 ||
		strings.Contains(svcName(p), "ssl") || strings.Contains(svcName(p), "https") {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d", scheme, target, p.Num)
	dir := mkDir(base, fmt.Sprintf("http_%d", p.Num))

	// httpx — fast probe: title, tech, status, redirects
	if has("httpx") {
		info("[%s] httpx → %s", target, url)
		run(ctx, filepath.Join(dir, "httpx.txt"), "httpx",
			"-u", url, "-title", "-tech-detect", "-status-code",
			"-follow-redirects", "-silent")
	}

	// robots.txt + sitemap
	run(ctx, filepath.Join(dir, "robots.txt"), "curl",
		"-sk", "-L", "--max-time", "10", url+"/robots.txt")
	run(ctx, filepath.Join(dir, "sitemap.xml"), "curl",
		"-sk", "-L", "--max-time", "10", url+"/sitemap.xml")

	// whatweb — technology fingerprint
	if has("whatweb") {
		info("[%s] whatweb → %s", target, url)
		run(ctx, filepath.Join(dir, "whatweb.txt"), "whatweb",
			"--color=never", "--no-errors", "-a", "3", url)
	}

	// sslscan — TLS config (HTTPS only)
	if scheme == "https" && has("sslscan") {
		info("[%s] sslscan → %s:%d", target, target, p.Num)
		run(ctx, filepath.Join(dir, "sslscan.txt"), "sslscan",
			"--no-colour", fmt.Sprintf("%s:%d", target, p.Num))
	}

	// screenshot — gowitness preferred, cutycapt fallback
	if t := firstTool("gowitness", "cutycapt"); t != "" {
		info("[%s] screenshot → %s", target, url)
		switch t {
		case "gowitness":
			run(ctx, filepath.Join(dir, "gowitness.log"), "gowitness",
				"single", "-u", url,
				"--screenshot-path", dir,
				"--disable-db")
		case "cutycapt":
			run(ctx, filepath.Join(dir, "cutycapt.log"), "cutycapt",
				"--url="+url,
				"--out="+filepath.Join(dir, "screenshot.png"))
		}
	}

	// directory brute force
	if wl := firstFile(dirWordlist); wl != "" {
		switch t := firstTool("feroxbuster", "gobuster", "ffuf"); t {
		case "feroxbuster":
			info("[%s] feroxbuster → %s", target, url)
			run(ctx, filepath.Join(dir, "ferox.txt"), "feroxbuster",
				"-u", url, "-w", wl, "-t", "50", "--depth", "3",
				"--no-state", "--silent", "-k")
		case "gobuster":
			info("[%s] gobuster → %s", target, url)
			run(ctx, filepath.Join(dir, "gobuster.txt"), "gobuster", "dir",
				"-u", url, "-w", wl, "-t", "40", "-q", "-k")
		case "ffuf":
			info("[%s] ffuf → %s", target, url)
			run(ctx, filepath.Join(dir, "ffuf.txt"), "ffuf",
				"-u", url+"/FUZZ", "-w", wl, "-t", "50", "-s", "-k")
		}
	}

	// nikto — allowed in OSCP; hard cap at 3 min to avoid hanging
	if has("nikto") {
		info("[%s] nikto → %s (max 3min)", target, url)
		run(ctx, filepath.Join(dir, "nikto.txt"), "nikto",
			"-ask=no", "-nointeractive", "-maxtime", "180",
			"-host", url)
	}

	good("[%s] http:%d ✓", target, p.Num)
}

// ─────────── SMB ─────────────────────────────────────────────────────────

func scanSMB(ctx context.Context, target, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	dir := mkDir(base, "smb")
	info("[%s] smb enum", target)

	// nmap vuln + enum scripts
	run(ctx, filepath.Join(dir, "nmap_smb.txt"), "nmap",
		"-Pn", "-p", "139,445",
		"--script", "smb-vuln*,smb-enum-shares,smb-enum-users,smb-security-mode,smb2-security-mode",
		target)

	// nbtscan — NetBIOS info
	if has("nbtscan") {
		run(ctx, filepath.Join(dir, "nbtscan.txt"), "nbtscan", "-r", target+"/32")
	}

	// smbmap — permissions map
	if has("smbmap") {
		run(ctx, filepath.Join(dir, "smbmap.txt"), "smbmap", "-H", target)
		run(ctx, filepath.Join(dir, "smbmap_recurse.txt"), "smbmap", "-H", target, "-R")
	}

	// smbclient — list shares anonymous
	if has("smbclient") {
		run(ctx, filepath.Join(dir, "smbclient_list.txt"), "smbclient",
			"-L", "//"+target, "-N")
	}

	// enum4linux(-ng) — full SMB enum
	if t := firstTool("enum4linux-ng", "enum4linux"); t != "" {
		flag := "-A"
		if t == "enum4linux" {
			flag = "-a"
		}
		run(ctx, filepath.Join(dir, "enum4linux.txt"), t, flag, target)
	}

	// netexec/nxc — share list + anonymous
	if t := firstTool("nxc", "netexec"); t != "" {
		run(ctx, filepath.Join(dir, "nxc_shares.txt"),
			t, "smb", target, "-u", "", "-p", "", "--shares")
		run(ctx, filepath.Join(dir, "nxc_users.txt"),
			t, "smb", target, "-u", "", "-p", "", "--users")
	}

	// rpcclient — anonymous RPC enumeration
	if has("rpcclient") {
		run(ctx, filepath.Join(dir, "rpcclient_anon.txt"), "rpcclient",
			"-U", "", "-N", target, "-c",
			"enumdomusers;enumdomgroups;enumprinters;querydominfo")
	}

	good("[%s] smb ✓", target)
}

// ─────────── FTP ─────────────────────────────────────────────────────────

func scanFTP(ctx context.Context, target string, port int, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	dir := mkDir(base, "ftp")
	info("[%s] ftp (:%d)", target, port)
	run(ctx, filepath.Join(dir, "nmap_ftp.txt"), "nmap",
		"-Pn", "-p", strconv.Itoa(port),
		"--script", "ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor",
		target)
	// try anonymous list
	run(ctx, filepath.Join(dir, "ftp_anon_list.txt"), "curl",
		"-sk", "--max-time", "10", fmt.Sprintf("ftp://%s/", target),
		"--user", "anonymous:anonymous")
	good("[%s] ftp ✓", target)
}

// ─────────── SSH ─────────────────────────────────────────────────────────

func scanSSH(ctx context.Context, target string, port int, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	dir := mkDir(base, "ssh")
	info("[%s] ssh (:%d)", target, port)
	run(ctx, filepath.Join(dir, "nmap_ssh.txt"), "nmap",
		"-Pn", "-p", strconv.Itoa(port),
		"--script", "ssh2-enum-algos,ssh-auth-methods,ssh-hostkey",
		target)
	good("[%s] ssh ✓", target)
}

// ─────────── SMTP ─────────────────────────────────────────────────────────

func scanSMTP(ctx context.Context, target string, port int, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	dir := mkDir(base, "smtp")
	info("[%s] smtp (:%d)", target, port)

	run(ctx, filepath.Join(dir, "nmap_smtp.txt"), "nmap",
		"-Pn", "-p", strconv.Itoa(port),
		"--script", "smtp-commands,smtp-enum-users,smtp-open-relay,smtp-ntlm-info",
		target)

	// smtp-user-enum — VRFY/EXPN/RCPT username enum
	if has("smtp-user-enum") {
		if wl := firstFile(userWordlist); wl != "" {
			info("[%s] smtp-user-enum VRFY (:%d)", target, port)
			run(ctx, filepath.Join(dir, "smtp_usereneum.txt"), "smtp-user-enum",
				"-M", "VRFY", "-U", wl,
				"-t", target, "-p", strconv.Itoa(port))
		}
	}

	good("[%s] smtp ✓", target)
}

// ─────────── DNS ──────────────────────────────────────────────────────────

func scanDNS(ctx context.Context, target, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	dir := mkDir(base, "dns")
	info("[%s] dns zone transfer + enum", target)

	run(ctx, filepath.Join(dir, "nmap_dns.txt"), "nmap",
		"-Pn", "-p", "53",
		"--script", "dns-zone-transfer,dns-brute,dns-recursion,dns-srv-enum",
		target)

	if has("dig") {
		run(ctx, filepath.Join(dir, "dig_axfr.txt"), "dig", "@"+target, "axfr")
		run(ctx, filepath.Join(dir, "dig_any.txt"), "dig", "@"+target, "any")
	}

	good("[%s] dns ✓", target)
}

// ─────────── LDAP ─────────────────────────────────────────────────────────

func scanLDAP(ctx context.Context, target, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	dir := mkDir(base, "ldap")
	info("[%s] ldap anon enum", target)

	run(ctx, filepath.Join(dir, "ldapsearch_base.txt"), "ldapsearch",
		"-x", "-H", "ldap://"+target, "-s", "base", "-b", "")
	run(ctx, filepath.Join(dir, "ldapsearch_namingctx.txt"), "ldapsearch",
		"-x", "-H", "ldap://"+target, "-s", "base", "namingContexts")
	run(ctx, filepath.Join(dir, "nmap_ldap.txt"), "nmap",
		"-Pn", "-p", "389,636,3268,3269",
		"--script", "ldap-rootdse,ldap-search,ldap-novell-getpass",
		target)

	good("[%s] ldap ✓", target)
}

// ─────────── SNMP ─────────────────────────────────────────────────────────

func scanSNMP(ctx context.Context, target, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	dir := mkDir(base, "snmp")
	info("[%s] snmp v1+v2c", target)

	for _, c := range []string{"public", "private", "manager"} {
		run(ctx, filepath.Join(dir, "walk_"+c+".txt"),
			"snmpwalk", "-v1", "-c", c, target)
		// NET-SNMP extend: admins sometimes expose creds here
		run(ctx, filepath.Join(dir, "extend_"+c+".txt"),
			"snmpwalk", "-v1", "-c", c, target,
			"NET-SNMP-EXTEND-MIB::nsExtendObjects")
	}

	if has("onesixtyone") {
		if wl := firstFile(snmpWordlist); wl != "" {
			run(ctx, filepath.Join(dir, "onesixtyone.txt"),
				"onesixtyone", "-c", wl, target)
		}
	}

	good("[%s] snmp ✓", target)
}

// ─────────── RDP ──────────────────────────────────────────────────────────

func scanRDP(ctx context.Context, target, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	dir := mkDir(base, "rdp")
	info("[%s] rdp scripts", target)
	run(ctx, filepath.Join(dir, "nmap_rdp.txt"), "nmap",
		"-Pn", "-p", "3389",
		"--script", "rdp-enum-encryption,rdp-vuln-ms12-020,rdp-info",
		target)
	good("[%s] rdp ✓", target)
}

// ─────────── VNC ──────────────────────────────────────────────────────────

func scanVNC(ctx context.Context, target string, port int, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	dir := mkDir(base, "vnc")
	info("[%s] vnc (:%d)", target, port)
	run(ctx, filepath.Join(dir, "nmap_vnc.txt"), "nmap",
		"-Pn", "-p", strconv.Itoa(port),
		"--script", "vnc-info,vnc-title,realvnc-auth-bypass",
		target)
	good("[%s] vnc ✓", target)
}

// ─────────── WINRM ────────────────────────────────────────────────────────

func scanWinRM(ctx context.Context, target, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	dir := mkDir(base, "winrm")
	info("[%s] winrm detection (5985/5986)", target)
	run(ctx, filepath.Join(dir, "nmap_winrm.txt"), "nmap",
		"-Pn", "-p", "5985,5986",
		"--script", "http-auth-finder,http-title",
		target)
	if t := firstTool("nxc", "netexec"); t != "" {
		run(ctx, filepath.Join(dir, "nxc_winrm.txt"),
			t, "winrm", target, "-u", "", "-p", "")
	}
	good("[%s] winrm ✓", target)
}

// ─────────── NFS ──────────────────────────────────────────────────────────

func scanNFS(ctx context.Context, target, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	dir := mkDir(base, "nfs")
	info("[%s] nfs/rpc enum", target)

	// showmount — list exported shares (common OSCP easy win)
	if has("showmount") {
		run(ctx, filepath.Join(dir, "showmount.txt"), "showmount", "-e", target)
	}
	run(ctx, filepath.Join(dir, "nmap_nfs.txt"), "nmap",
		"-Pn", "-p", "111,2049",
		"--script", "nfs-ls,nfs-showmount,nfs-statfs,rpcinfo",
		target)

	// rpcinfo
	if has("rpcinfo") {
		run(ctx, filepath.Join(dir, "rpcinfo.txt"), "rpcinfo", "-p", target)
	}

	good("[%s] nfs ✓", target)
}

// ─────────── KERBEROS ─────────────────────────────────────────────────────

func scanKerberos(ctx context.Context, target, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	dir := mkDir(base, "kerberos")
	info("[%s] kerberos enum", target)

	run(ctx, filepath.Join(dir, "nmap_krb5.txt"), "nmap",
		"-Pn", "-p", "88",
		"--script", "krb5-enum-users",
		target)

	// kerbrute — AS-REP user enum (no password needed)
	if has("kerbrute") {
		if wl := firstFile(userWordlist); wl != "" {
			info("[%s] kerbrute userenum", target)
			run(ctx, filepath.Join(dir, "kerbrute.txt"), "kerbrute",
				"userenum", "--dc", target,
				"-d", target, wl)
		}
	}

	good("[%s] kerberos ✓", target)
}

// ─────────── REDIS ────────────────────────────────────────────────────────

func scanRedis(ctx context.Context, target string, port int, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	dir := mkDir(base, "redis")
	info("[%s] redis (:%d)", target, port)

	run(ctx, filepath.Join(dir, "nmap_redis.txt"), "nmap",
		"-Pn", "-p", strconv.Itoa(port),
		"--script", "redis-info",
		target)

	// redis-cli unauthenticated info dump (valkey-cli is the Arch/Valkey fork alias)
	if t := firstTool("redis-cli", "valkey-cli"); t != "" {
		run(ctx, filepath.Join(dir, "redis_info.txt"), t,
			"-h", target, "-p", strconv.Itoa(port), "info")
		run(ctx, filepath.Join(dir, "redis_config.txt"), t,
			"-h", target, "-p", strconv.Itoa(port), "config", "get", "*")
	}

	good("[%s] redis ✓", target)
}

// ─────────── MONGODB ──────────────────────────────────────────────────────

func scanMongoDB(ctx context.Context, target string, port int, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	dir := mkDir(base, "mongodb")
	info("[%s] mongodb (:%d)", target, port)
	run(ctx, filepath.Join(dir, "nmap_mongo.txt"), "nmap",
		"-Pn", "-p", strconv.Itoa(port),
		"--script", "mongodb-info,mongodb-databases",
		target)
	good("[%s] mongodb ✓", target)
}

// ─────────── MSSQL ────────────────────────────────────────────────────────

func scanMSSQL(ctx context.Context, target, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	dir := mkDir(base, "mssql")
	info("[%s] mssql scripts", target)
	run(ctx, filepath.Join(dir, "nmap_mssql.txt"), "nmap",
		"-Pn", "-p", "1433,1434",
		"--script", "ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-ntlm-info",
		target)
	if t := firstTool("nxc", "netexec"); t != "" {
		run(ctx, filepath.Join(dir, "nxc_mssql.txt"),
			t, "mssql", target, "-u", "", "-p", "")
	}
	good("[%s] mssql ✓", target)
}

// ─────────── MYSQL ────────────────────────────────────────────────────────

func scanMySQL(ctx context.Context, target, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	dir := mkDir(base, "mysql")
	info("[%s] mysql scripts", target)
	run(ctx, filepath.Join(dir, "nmap_mysql.txt"), "nmap",
		"-Pn", "-p", "3306",
		"--script", "mysql-info,mysql-empty-password,mysql-databases,mysql-users,mysql-audit",
		target)
	good("[%s] mysql ✓", target)
}

// ─────────── RSYNC ────────────────────────────────────────────────────────

func scanRsync(ctx context.Context, target, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	dir := mkDir(base, "rsync")
	info("[%s] rsync module list", target)
	run(ctx, filepath.Join(dir, "nmap_rsync.txt"), "nmap",
		"-Pn", "-p", "873",
		"--script", "rsync-list-modules",
		target)
	// list modules anonymously
	run(ctx, filepath.Join(dir, "rsync_list.txt"), "rsync",
		"--list-only", fmt.Sprintf("rsync://%s/", target))
	good("[%s] rsync ✓", target)
}

// ─────────── TELNET ───────────────────────────────────────────────────────

func scanTelnet(ctx context.Context, target string, port int, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	dir := mkDir(base, "telnet")
	info("[%s] telnet scripts (:%d)", target, port)
	run(ctx, filepath.Join(dir, "nmap_telnet.txt"), "nmap",
		"-Pn", "-p", strconv.Itoa(port),
		"--script", "telnet-encryption,telnet-ntlm-info",
		target)
	good("[%s] telnet ✓", target)
}

// ─────────── ORACLE ───────────────────────────────────────────────────────

func scanOracle(ctx context.Context, target, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	dir := mkDir(base, "oracle")
	info("[%s] oracle scripts", target)
	run(ctx, filepath.Join(dir, "nmap_oracle.txt"), "nmap",
		"-Pn", "-p", "1521,1522,1526",
		"--script", "oracle-tns-version,oracle-sid-brute",
		target)
	good("[%s] oracle ✓", target)
}

// ─────────── UDP ──────────────────────────────────────────────────────────

func scanUDP(ctx context.Context, target, base string, wg *sync.WaitGroup) {
	defer wg.Done()
	info("[%s] udp top-20", target)
	gnmap := filepath.Join(base, "udp.gnmap")
	nmapUDP(ctx, filepath.Join(base, "udp_top20.txt"),
		"-Pn", "-sU", "-sV", "--top-ports", "20",
		"-oG", gnmap, target)

	data, _ := os.ReadFile(gnmap)
	var found []string
	for _, m := range regexp.MustCompile(`(\d+)/open/udp//([^/]*)//`).FindAllStringSubmatch(string(data), -1) {
		svc := strings.TrimSpace(m[2])
		if svc == "" {
			svc = "unknown"
		}
		found = append(found, m[1]+"/"+svc)
	}
	if len(found) > 0 {
		good("[%s] UDP open: %s", target, strings.Join(found, "  "))
	}
	good("[%s] udp ✓", target)
}

// ─────────── REPORT ───────────────────────────────────────────────────────

func generateReport(target, base string, tcpPorts []string, services []Port, start time.Time) {
	f, err := os.Create(filepath.Join(base, "report.md"))
	if err != nil {
		return
	}
	defer f.Close()

	fmt.Fprintf(f, "# autorecon2 recon — %s\n", target)
	fmt.Fprintf(f, "**Date:** %s\n\n", time.Now().Format("2006-01-02 15:04"))

	fmt.Fprintf(f, "## Open TCP Ports\n```\n%s\n```\n\n", strings.Join(tcpPorts, ", "))

	if len(services) > 0 {
		fmt.Fprintf(f, "## Services\n\n| Port | Service |\n|------|----------|\n")
		for _, s := range services {
			fmt.Fprintf(f, "| %d | %s |\n", s.Num, s.Name)
		}
		fmt.Fprintln(f)
	}

	// quick wins checklist
	fmt.Fprintf(f, "## Quick Wins to Check\n\n")
	for _, s := range services {
		switch {
		case isHTTP(s):
			fmt.Fprintf(f, "- [ ] HTTP %d — check ferox.txt, nikto.txt, httpx.txt\n", s.Num)
		case s.Num == 445 || s.Num == 139:
			fmt.Fprintf(f, "- [ ] SMB — check enum4linux.txt, smbmap.txt, nmap_smb.txt (CVEs)\n")
		case s.Num == 21:
			fmt.Fprintf(f, "- [ ] FTP — check ftp-anon in nmap_ftp.txt\n")
		case s.Num == 2049 || s.Num == 111:
			fmt.Fprintf(f, "- [ ] NFS — check showmount.txt for exposed shares\n")
		case isSMTP(s):
			fmt.Fprintf(f, "- [ ] SMTP — check smtp_userenum.txt for valid usernames\n")
		case s.Num == 88:
			fmt.Fprintf(f, "- [ ] Kerberos — check kerbrute.txt, try AS-REP roasting\n")
		case s.Num == 6379:
			fmt.Fprintf(f, "- [ ] Redis — check redis_info.txt for unauthenticated access\n")
		case s.Num == 3306:
			fmt.Fprintf(f, "- [ ] MySQL — check mysql-empty-password in nmap_mysql.txt\n")
		case s.Num == 5985 || s.Num == 5986:
			fmt.Fprintf(f, "- [ ] WinRM — try evil-winrm if creds found\n")
		case s.Num == 389 || s.Num == 636:
			fmt.Fprintf(f, "- [ ] LDAP — check ldapsearch_base.txt for domain info\n")
		case s.Num == 161:
			fmt.Fprintf(f, "- [ ] SNMP — check extend_public.txt for creds in extend MIB\n")
		}
	}

	fmt.Fprintf(f, "\n## Duration\n%s\n", time.Since(start).Round(time.Second))
	fmt.Fprintf(f, "\n## Output Directory\n`%s`\n", base)
}

// ─────────── ORCHESTRATOR ────────────────────────────────────────────────

func scanTarget(target string) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	base := mkDir(outDir, target)
	start := time.Now()
	info("[%s] start → %s", target, base)

	// ── Phase 1: fast port discovery ─────────────────────────────────────
	var tcpPorts []string

	if has("rustscan") {
		out, err := exec.CommandContext(ctx,
			"rustscan", "-a", target, "-b", "2500", "--ulimit", "5000", "-g",
		).Output()
		if err == nil {
			tcpPorts = parseRustscan(string(out))
			os.WriteFile(filepath.Join(base, "rustscan.txt"), out, 0644)
		}
	}

	if len(tcpPorts) == 0 {
		if has("rustscan") {
			warn("[%s] rustscan returned no ports — fallback nmap -p-", target)
		} else {
			info("[%s] rustscan not found — nmap -p- --min-rate 5000", target)
		}
		gnmap := filepath.Join(base, "disc.gnmap")
		run(ctx, filepath.Join(base, "disc.txt"), "nmap",
			"-Pn", "-n", "-T5", "--min-rate", "5000", "--open", "-p-",
			"-oG", gnmap, target)
		tcpPorts = parseGnmap(gnmap)
	}

	if len(tcpPorts) == 0 {
		warn("[%s] no open TCP ports — running UDP + SNMP only", target)
	} else {
		good("[%s] TCP open: [%s]", target, strings.Join(tcpPorts, ", "))
	}

	// ── Phase 2: service detection on discovered ports ────────────────────
	var services []Port
	if len(tcpPorts) > 0 {
		info("[%s] service detection on %d port(s)", target, len(tcpPorts))
		run(ctx, filepath.Join(base, "nmap_svc.txt"), "nmap",
			"-Pn", "-sV", "-sC", "-A", "--osscan-guess",
			"-p", strings.Join(tcpPorts, ","),
			"-oA", filepath.Join(base, "nmap_svc"),
			target)
		services = parseServices(filepath.Join(base, "nmap_svc.gnmap"))
	}

	if len(services) > 0 {
		tags := make([]string, len(services))
		for i, s := range services {
			tags[i] = fmt.Sprintf("%d/%s", s.Num, s.Name)
		}
		good("[%s] services: %s", target, strings.Join(tags, "  "))
	}

	// ── Phase 3: goroutine per service ────────────────────────────────────
	var wg sync.WaitGroup
	dispatched := map[string]bool{}

	dispatch := func(key string, fn func()) {
		if dispatched[key] {
			return
		}
		dispatched[key] = true
		wg.Add(1)
		go fn()
	}

	for _, svc := range services {
		p := svc
		name := svcName(p)

		switch {
		case isHTTP(p):
			dispatch(fmt.Sprintf("http%d", p.Num), func() { scanHTTP(ctx, target, p, base, &wg) })
		case p.Num == 445 || p.Num == 139:
			dispatch("smb", func() { scanSMB(ctx, target, base, &wg) })
		case p.Num == 21 || strings.Contains(name, "ftp"):
			dispatch(fmt.Sprintf("ftp%d", p.Num), func() { scanFTP(ctx, target, p.Num, base, &wg) })
		case p.Num == 22 || strings.Contains(name, "ssh"):
			dispatch(fmt.Sprintf("ssh%d", p.Num), func() { scanSSH(ctx, target, p.Num, base, &wg) })
		case isSMTP(p):
			dispatch(fmt.Sprintf("smtp%d", p.Num), func() { scanSMTP(ctx, target, p.Num, base, &wg) })
		case p.Num == 53 || strings.Contains(name, "domain"):
			dispatch("dns", func() { scanDNS(ctx, target, base, &wg) })
		case p.Num == 389 || p.Num == 636 || p.Num == 3268 || strings.Contains(name, "ldap"):
			dispatch("ldap", func() { scanLDAP(ctx, target, base, &wg) })
		case p.Num == 88 || strings.Contains(name, "kerberos"):
			dispatch("kerberos", func() { scanKerberos(ctx, target, base, &wg) })
		case p.Num == 3389 || strings.Contains(name, "ms-wbt"):
			dispatch("rdp", func() { scanRDP(ctx, target, base, &wg) })
		case p.Num == 5985 || p.Num == 5986:
			dispatch("winrm", func() { scanWinRM(ctx, target, base, &wg) })
		case p.Num == 111 || p.Num == 2049 || strings.Contains(name, "nfs"):
			dispatch("nfs", func() { scanNFS(ctx, target, base, &wg) })
		case p.Num == 6379 || strings.Contains(name, "redis"):
			dispatch(fmt.Sprintf("redis%d", p.Num), func() { scanRedis(ctx, target, p.Num, base, &wg) })
		case p.Num == 27017 || strings.Contains(name, "mongodb"):
			dispatch(fmt.Sprintf("mongo%d", p.Num), func() { scanMongoDB(ctx, target, p.Num, base, &wg) })
		case p.Num == 3306 || strings.Contains(name, "mysql"):
			dispatch("mysql", func() { scanMySQL(ctx, target, base, &wg) })
		case p.Num == 1433 || strings.Contains(name, "ms-sql"):
			dispatch("mssql", func() { scanMSSQL(ctx, target, base, &wg) })
		case p.Num == 873 || strings.Contains(name, "rsync"):
			dispatch("rsync", func() { scanRsync(ctx, target, base, &wg) })
		case p.Num == 23 || strings.Contains(name, "telnet"):
			dispatch("telnet", func() { scanTelnet(ctx, target, p.Num, base, &wg) })
		case p.Num == 1521 || strings.Contains(name, "oracle"):
			dispatch("oracle", func() { scanOracle(ctx, target, base, &wg) })
		case p.Num >= 5900 && p.Num <= 5910 || strings.Contains(name, "vnc"):
			dispatch(fmt.Sprintf("vnc%d", p.Num), func() { scanVNC(ctx, target, p.Num, base, &wg) })
		}
	}

	// always run — snmp(udp/161) + udp top-20
	dispatch("udp", func() { scanUDP(ctx, target, base, &wg) })
	dispatch("snmp", func() { scanSNMP(ctx, target, base, &wg) })

	wg.Wait()

	// summary report
	generateReport(target, base, tcpPorts, services, start)

	good("[%s] %s✓ complete%s in %s → %s", target, cB, cRst,
		time.Since(start).Round(time.Second), base)
}

// ─────────── MAIN ────────────────────────────────────────────────────────

func main() {
	fixSudoPath()

	flag.StringVar(&outDir, "o", "recon", "output directory")
	flag.BoolVar(&verbose, "v", false, "verbose: stream all tool output to stdout")
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, banner+"\n\nUsage: autorecon2 [flags] <target> [target ...]\n\nFlags:\n")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Examples:
  autorecon2 10.10.10.5                     # OSCP safe
  autorecon2 -o /tmp/recon 10.10.10.5 10.10.10.6 10.10.10.7
  sudo autorecon2 10.10.10.5                # enables UDP scan
`)
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	fmt.Println(cB + banner + cRst + "\n")

	if !has("nmap") {
		fmt.Fprintln(os.Stderr, "[!] nmap is required. apt install nmap")
		os.Exit(1)
	}

	all := []string{
		"rustscan", "nmap", "httpx", "curl",
		"feroxbuster", "gobuster", "ffuf",
		"nikto", "whatweb", "sslscan", "gowitness",
		"enum4linux", "nxc", "smbmap", "smbclient", "rpcclient",
		"snmpwalk", "onesixtyone",
		"ldapsearch", "dig",
		"showmount", "rpcinfo",
		"smtp-user-enum", "kerbrute",
		"redis-cli", "valkey-cli", "rsync",
	}
	var av, miss []string
	for _, t := range all {
		if has(t) {
			av = append(av, cG+t+cRst)
		} else {
			miss = append(miss, t)
		}
	}
	info("tools: %s", strings.Join(av, "  "))
	if len(miss) > 0 {
		warn("missing (skip): %s", strings.Join(miss, ", "))
	}
	fmt.Println()

	os.MkdirAll(outDir, 0755)

	var wg sync.WaitGroup
	for _, t := range flag.Args() {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			scanTarget(target)
		}(t)
	}
	wg.Wait()

	fmt.Printf("%s[✓]%s All done → %s%s%s\n", cG, cRst, cB, outDir, cRst)
}
