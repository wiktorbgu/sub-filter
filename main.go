package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

const (
	defaultSourcesFile  = "./config/sub.txt"
	defaultBadWordsFile = "./config/bad.txt"
	defaultUAgentFile   = "./config/uagent.txt"
	defaultCacheDir     = "./cache"
	maxIDLength         = 64
	maxURILength        = 4096
	maxUserinfoLength   = 1024
	maxSourceBytes      = 10 * 1024 * 1024 // 10 MB
)

type SafeSource struct {
	URL string
	IP  net.IP
}

type SourceMap map[string]*SafeSource

var (
	cacheDir   string
	cacheTTL   time.Duration
	sources    SourceMap
	badWords   []string
	allowedUA  []string
	validIDRe  = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	ssCipherRe = regexp.MustCompile(`^[a-zA-Z0-9_+-]+$`)
	hostRegex  = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

	// Rate limiting with TTL
	ipLimiter    = make(map[string]*rate.Limiter)
	ipLastSeen   = make(map[string]time.Time)
	limiterMutex sync.RWMutex

	// Deduplicate concurrent fetches
	fetchGroup singleflight.Group

	builtinAllowedPrefixes = []string{"clash", "happ"}
)

type LineProcessor func(string) string

func loadTextFile(filename string, processor LineProcessor) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	if b, err := reader.Peek(3); err == nil && bytes.Equal(b, []byte{0xEF, 0xBB, 0xBF}) {
		reader.Discard(3)
	}

	var result []string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if processor != nil {
			line = processor(line)
		}
		result = append(result, line)
	}
	return result, scanner.Err()
}

func isValidSourceURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if host == "localhost" {
		return false
	}
	if strings.HasPrefix(host, "127.") {
		return false
	}
	if strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return false
	}
	if strings.HasPrefix(host, "xn--") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsMulticast() {
			return false
		}
	}
	return true
}

func isIPAllowed(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	return true
}

func getLimiter(ip string) *rate.Limiter {
	limiterMutex.Lock()
	defer limiterMutex.Unlock()
	ipLastSeen[ip] = time.Now()
	if limiter, exists := ipLimiter[ip]; exists {
		return limiter
	}
	limiter := rate.NewLimiter(rate.Every(100*time.Millisecond), 5)
	ipLimiter[ip] = limiter
	return limiter
}

func cleanupLimiters() {
	ticker := time.NewTicker(2 * time.Minute)
	go func() {
		for range ticker.C {
			limiterMutex.Lock()
			now := time.Now()
			for ip, last := range ipLastSeen {
				if now.Sub(last) > 30*time.Minute {
					delete(ipLimiter, ip)
					delete(ipLastSeen, ip)
				}
			}
			limiterMutex.Unlock()
		}
	}()
}

func decodeUserInfo(s string) ([]byte, error) {
	isURLSafe := strings.ContainsAny(s, "-_")
	isPadded := strings.HasSuffix(s, "=")

	var enc *base64.Encoding
	switch {
	case isURLSafe && isPadded:
		enc = base64.URLEncoding
	case isURLSafe && !isPadded:
		enc = base64.RawURLEncoding
	case !isURLSafe && isPadded:
		enc = base64.StdEncoding
	case !isURLSafe && !isPadded:
		enc = base64.RawStdEncoding
	default:
		enc = base64.RawURLEncoding
	}
	return enc.DecodeString(s)
}

func isValidUserAgent(ua string) bool {
	lowerUA := strings.ToLower(ua)
	for _, prefix := range builtinAllowedPrefixes {
		if strings.HasPrefix(lowerUA, prefix) {
			return true
		}
	}
	for _, allowed := range allowedUA {
		if allowed == "" {
			continue
		}
		if strings.Contains(lowerUA, strings.ToLower(allowed)) {
			return true
		}
	}
	return false
}

func isValidHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.HasPrefix(host, "xn--") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	return hostRegex.MatchString(strings.ToLower(host))
}

func isValidPort(port int) bool {
	return port > 0 && port <= 65535
}

func fullyDecode(s string) string {
	for {
		decoded, err := url.QueryUnescape(s)
		if err != nil || decoded == s {
			return s
		}
		s = decoded
	}
}

func isForbiddenAnchor(fragment string) bool {
	if fragment == "" {
		return false
	}
	decoded := fullyDecode(fragment)
	decodedLower := strings.ToLower(decoded)
	for _, word := range badWords {
		if word != "" && strings.Contains(decodedLower, word) {
			return true
		}
	}
	return false
}

// === URI Processing ===

func processVLESS(raw string) string {
	if len(raw) > maxURILength {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "vless" {
		return ""
	}

	uuid := u.User.Username()
	host := u.Hostname()
	portStr := u.Port()

	if portStr == "" || uuid == "" || len(uuid) > maxIDLength {
		return ""
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || !isValidPort(port) {
		return ""
	}

	if !isValidHost(host) || isForbiddenAnchor(u.Fragment) {
		return ""
	}

	queryVals := u.Query()
	if queryVals.Get("allowInsecure") == "true" {
		return ""
	}

	// 🔒 Запрет VLESS без шифрования (security=none)
	if queryVals.Get("security") == "none" {
		return ""
	}

	// Требуем SNI при использовании REALITY
	if queryVals.Get("security") == "reality" && queryVals.Get("sni") == "" {
		return ""
	}

	// Проверяем, что flow используется только с reality
	flow := queryVals.Get("flow")
	if flow != "" && queryVals.Get("security") != "reality" {
		return ""
	}

	if alpnList := queryVals["alpn"]; len(alpnList) > 0 {
		queryVals["alpn"] = alpnList[:1]
	}

	var buf strings.Builder
	buf.WriteString("vless://")
	buf.WriteString(uuid)
	buf.WriteString("@")
	buf.WriteString(net.JoinHostPort(host, portStr))
	if u.Path != "" {
		buf.WriteString(u.Path)
	}
	if len(queryVals) > 0 {
		buf.WriteString("?")
		buf.WriteString(queryVals.Encode())
	}
	if u.Fragment != "" {
		buf.WriteString("#")
		buf.WriteString(u.Fragment)
	}
	return buf.String()
}

func processVMess(raw string) string {
	if len(raw) > maxURILength {
		return ""
	}

	if !strings.HasPrefix(strings.ToLower(raw), "vmess://") {
		return ""
	}

	b64 := strings.TrimPrefix(raw, "vmess://")
	if b64 == "" {
		return ""
	}

	decoded, err := decodeUserInfo(b64)
	if err != nil {
		return ""
	}

	var vm map[string]interface{}
	if err := json.Unmarshal(decoded, &vm); err != nil {
		return ""
	}

	ps, _ := vm["ps"].(string)
	add, _ := vm["add"].(string)
	port, ok := vm["port"].(float64)
	if !ok {
		return ""
	}
	id, _ := vm["id"].(string)

	if add == "" || id == "" {
		return ""
	}

	if int(port) <= 0 || int(port) > 65535 {
		return ""
	}

	if !isValidHost(add) {
		return ""
	}

	if isForbiddenAnchor(ps) {
		return ""
	}

	net, _ := vm["net"].(string)
	if net == "grpc" {
		svc, _ := vm["serviceName"].(string)
		if svc == "" {
			return ""
		}
	}

	tls, _ := vm["tls"].(string)
	// Блокируем незашифрованный VMess (кроме gRPC, где иногда допустимо без TLS)
	if net != "grpc" && tls != "tls" {
		return ""
	}

	reencoded, err := json.Marshal(vm)
	if err != nil {
		return ""
	}

	finalB64 := base64.StdEncoding.EncodeToString(reencoded)
	return "vmess://" + finalB64
}

func processTrojan(raw string) string {
	if len(raw) > maxURILength {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "trojan" {
		return ""
	}

	password := u.User.Username()
	if password == "" {
		return ""
	}

	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		return ""
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || !isValidPort(port) || !isValidHost(host) {
		return ""
	}

	if isForbiddenAnchor(u.Fragment) {
		return ""
	}

	queryVals := u.Query()
	/*if queryVals.Get("allowInsecure") == "true" {
		return ""
	}*/

	if queryVals.Get("type") == "grpc" && queryVals.Get("serviceName") == "" {
		return ""
	}

	var buf strings.Builder
	buf.WriteString("trojan://")
	buf.WriteString(password) // Исправлено: пароль НЕ экранируется
	buf.WriteString("@")
	buf.WriteString(net.JoinHostPort(host, portStr))
	if len(queryVals) > 0 {
		buf.WriteString("?")
		buf.WriteString(queryVals.Encode())
	}
	if u.Fragment != "" {
		buf.WriteString("#")
		buf.WriteString(u.Fragment)
	}
	return buf.String()
}

func processSS(raw string) string {
	if len(raw) > maxURILength {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "ss" {
		return ""
	}

	userinfo := u.User.String()
	if userinfo == "" || len(userinfo) > maxUserinfoLength {
		return ""
	}

	decoded, decodeErr := decodeUserInfo(userinfo)
	if decodeErr != nil {
		return ""
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return ""
	}
	cipher, password := parts[0], parts[1]
	if cipher == "" || password == "" || !ssCipherRe.MatchString(cipher) {
		return ""
	}

	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		return ""
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || !isValidPort(port) || !isValidHost(host) {
		return ""
	}

	if isForbiddenAnchor(u.Fragment) {
		return ""
	}

	newUser := base64.RawURLEncoding.EncodeToString([]byte(cipher + ":" + password))
	var buf strings.Builder
	buf.WriteString("ss://")
	buf.WriteString(newUser)
	buf.WriteString("@")
	buf.WriteString(net.JoinHostPort(host, portStr))
	if u.Fragment != "" {
		buf.WriteString("#")
		buf.WriteString(u.Fragment)
	}
	return buf.String()
}

func isPathSafe(p, baseDir string) bool {
	cleanPath := filepath.Clean(p)
	rel, err := filepath.Rel(baseDir, cleanPath)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."
}

func serveFile(w http.ResponseWriter, r *http.Request, content []byte, sourceURL, id string) {
	filename := "filtered_" + id + ".txt"
	if u, err := url.Parse(sourceURL); err == nil {
		base := path.Base(u.Path)
		if base != "" && regexp.MustCompile(`^[a-zA-Z0-9._-]+\.txt$`).MatchString(base) {
			filename = base
		}
	}
	filename = regexp.MustCompile(`[^a-zA-Z0-9._-]`).ReplaceAllString(filename, "_")
	if !strings.HasSuffix(strings.ToLower(filename), ".txt") {
		filename += ".txt"
	}
	filename = filepath.Base(filename)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.Write(content)
}

func handler(w http.ResponseWriter, r *http.Request) {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}
	limiter := getLimiter(clientIP)
	if !limiter.Allow() {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	if !isValidUserAgent(r.Header.Get("User-Agent")) {
		http.Error(w, "Forbidden: invalid User-Agent", http.StatusForbidden)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" || len(id) > maxIDLength || !validIDRe.MatchString(id) {
		http.Error(w, "Invalid id", http.StatusBadRequest)
		return
	}

	source, exists := sources[id]
	if !exists {
		http.Error(w, "Invalid id", http.StatusBadRequest)
		return
	}

	parsedSource, err := url.Parse(source.URL)
	if err != nil || parsedSource.Host == "" {
		http.Error(w, "Invalid source URL", http.StatusBadRequest)
		return
	}
	host := parsedSource.Hostname()
	if !isValidHost(host) {
		http.Error(w, "Invalid source host", http.StatusBadRequest)
		return
	}

	origCache := filepath.Join(cacheDir, "orig_"+id+".txt")
	modCache := filepath.Join(cacheDir, "mod_"+id+".txt")
	rejectedCache := filepath.Join(cacheDir, "rejected_"+id+".txt")

	if !isPathSafe(origCache, cacheDir) || !isPathSafe(modCache, cacheDir) || !isPathSafe(rejectedCache, cacheDir) {
		http.Error(w, "Invalid id", http.StatusBadRequest)
		return
	}

	if info, err := os.Stat(modCache); err == nil && time.Since(info.ModTime()) <= cacheTTL {
		if content, err := os.ReadFile(modCache); err == nil {
			serveFile(w, r, content, source.URL, id)
			return
		}
	}

	var origContent []byte
	if info, err := os.Stat(origCache); err == nil && time.Since(info.ModTime()) <= cacheTTL {
		if content, err := os.ReadFile(origCache); err == nil {
			origContent = content
		}
	}

	if origContent == nil {
		_, portStr, _ := net.SplitHostPort(parsedSource.Host)
		if portStr == "" {
			if parsedSource.Scheme == "https" {
				portStr = "443"
			} else {
				portStr = "80"
			}
		}

		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					dialer := &net.Dialer{Timeout: 5 * time.Second}
					return dialer.DialContext(ctx, network, net.JoinHostPort(source.IP.String(), portStr))
				},
				TLSClientConfig: &tls.Config{
					ServerName: host,
				},
				MaxIdleConns:    10,
				IdleConnTimeout: 30 * time.Second,
			},
		}

		result, err, _ := fetchGroup.Do(id, func() (interface{}, error) {
			req, err := http.NewRequest("GET", source.URL, nil)
			if err != nil {
				return nil, fmt.Errorf("invalid source URL: %w", err)
			}
			req.Header.Set("User-Agent", "go-filter/1.0")

			resp, err := client.Do(req)
			if err != nil {
				return nil, fmt.Errorf("fetch failed: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 400 {
				return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
			}

			content, err := io.ReadAll(io.LimitReader(resp.Body, maxSourceBytes))
			if err != nil {
				return nil, fmt.Errorf("read failed: %w", err)
			}

			tmpFile := origCache + ".tmp"
			if writeErr := os.WriteFile(tmpFile, content, 0o644); writeErr == nil {
				os.Rename(tmpFile, origCache)
			}
			return content, nil
		})

		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to fetch source %s: %v", source.URL, err), http.StatusBadGateway)
			return
		}
		origContent = result.([]byte)
	}

	var out []string
	var rejectedLines []string

	lines := bytes.Split(origContent, []byte("\n"))
	for _, lineBytes := range lines {
		originalLine := strings.TrimRight(string(lineBytes), "\r\n")
		if originalLine == "" || strings.HasPrefix(originalLine, "#") {
			continue
		}

		if len(originalLine) > maxURILength {
			rejectedLines = append(rejectedLines, "# REASON: Line too long", originalLine)
			continue
		}

		lowerLine := strings.ToLower(originalLine)
		var processedLine string
		var reason string

		switch {
		case strings.HasPrefix(lowerLine, "vless://"):
			processedLine = processVLESS(originalLine)
			if processedLine == "" {
				reason = "Invalid or unsafe VLESS link"
			}
		case strings.HasPrefix(lowerLine, "vmess://"):
			processedLine = processVMess(originalLine)
			if processedLine == "" {
				reason = "Invalid or unsafe VMess link"
			}
		case strings.HasPrefix(lowerLine, "trojan://"):
			processedLine = processTrojan(originalLine)
			if processedLine == "" {
				reason = "Invalid or unsafe Trojan link"
			}
		case strings.HasPrefix(lowerLine, "ss://"):
			processedLine = processSS(originalLine)
			if processedLine == "" {
				reason = "Invalid or unsafe Shadowsocks link"
			}
		default:
			reason = "Unsupported protocol"
		}

		if processedLine != "" {
			out = append(out, processedLine)
		} else {
			rejectedLines = append(rejectedLines, "# REASON: "+reason, originalLine)
		}
	}

	if len(rejectedLines) > 0 {
		rejectedContent := strings.Join(rejectedLines, "\n")
		tmpRejectedFile := rejectedCache + ".tmp"
		if err := os.WriteFile(tmpRejectedFile, []byte(rejectedContent), 0o644); err == nil {
			os.Rename(tmpRejectedFile, rejectedCache)
		}
	} else {
		if _, err := os.Stat(rejectedCache); err == nil {
			os.Remove(rejectedCache)
		}
	}

	sourceHost := "unknown"
	if parsedSource, err := url.Parse(source.URL); err == nil && parsedSource.Host != "" {
		if h, _, err := net.SplitHostPort(parsedSource.Host); err == nil {
			sourceHost = h
		} else {
			sourceHost = parsedSource.Host
		}
	}

	updateInterval := int(cacheTTL.Seconds() / 3600)
	if updateInterval < 1 {
		updateInterval = 1
	}

	profileTitle := fmt.Sprintf("#profile-title: %s filtered %s", sourceHost, id)
	profileInterval := fmt.Sprintf("#profile-update-interval: %d", updateInterval)

	finalLines := []string{profileTitle, profileInterval, ""}
	finalLines = append(finalLines, out...)
	final := strings.Join(finalLines, "\n")

	tmpFile := modCache + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(final), 0o644); err == nil {
		os.Rename(tmpFile, modCache)
	}

	serveFile(w, r, []byte(final), source.URL, id)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <port> [cache_ttl_seconds] [sources_file] [bad_words_file] [uagent_file]\n", os.Args[0])
		os.Exit(1)
	}

	port := os.Args[1]
	cacheTTLSeconds := 1800
	if len(os.Args) >= 3 {
		if sec, err := strconv.Atoi(os.Args[2]); err == nil && sec > 0 {
			cacheTTLSeconds = sec
		}
	}
	sourcesFile := defaultSourcesFile
	if len(os.Args) >= 4 {
		sourcesFile = os.Args[3]
	}
	badWordsFile := defaultBadWordsFile
	if len(os.Args) >= 5 {
		badWordsFile = os.Args[4]
	}
	uagentFile := defaultUAgentFile
	if len(os.Args) >= 6 {
		uagentFile = os.Args[5]
	}

	cacheTTL = time.Duration(cacheTTLSeconds) * time.Second
	cacheDir = defaultCacheDir

	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot create cache dir: %v\n", err)
		os.Exit(1)
	}

	// Load and validate sources with IP resolution
	lines, err := loadTextFile(sourcesFile, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load sources: %v\n", err)
		os.Exit(1)
	}
	sources = make(SourceMap)
	validIndex := 1
	for _, line := range lines {
		if !isValidSourceURL(line) {
			fmt.Fprintf(os.Stderr, "⚠️  Skipping invalid or unsafe source URL: %s\n", line)
			continue
		}

		u, _ := url.Parse(line)
		host := u.Hostname()
		portStr := u.Port()
		if portStr == "" {
			if u.Scheme == "https" {
				portStr = "443"
			} else {
				portStr = "80"
			}
		}

		ips, err := net.LookupIP(host)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Failed to resolve host %s: %v\n", host, err)
			continue
		}

		var allowedIP net.IP
		for _, ip := range ips {
			if isIPAllowed(ip) {
				allowedIP = ip
				break
			}
		}
		if allowedIP == nil {
			fmt.Fprintf(os.Stderr, "⚠️  No allowed public IP for host %s\n", host)
			continue
		}

		sources[strconv.Itoa(validIndex)] = &SafeSource{
			URL: line,
			IP:  allowedIP,
		}
		validIndex++
	}
	if len(sources) == 0 {
		fmt.Fprintf(os.Stderr, "No valid sources loaded. Exiting.\n")
		os.Exit(1)
	}

	badWords, err = loadTextFile(badWordsFile, strings.ToLower)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load bad words: %v (using empty list)\n", err)
		badWords = []string{}
	}

	allowedUA, err = loadTextFile(uagentFile, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Note: using built-in User-Agent rules only (no %s or error: %v)\n", uagentFile, err)
		allowedUA = []string{}
	}

	cleanupLimiters()
	http.HandleFunc("/filter", handler)
	fmt.Printf("Server starting on :%s\n", port)
	fmt.Printf("Valid sources loaded: %d\n", len(sources))
	fmt.Printf("Bad words: %s\n", badWordsFile)
	fmt.Printf("User-Agent file: %s\n", uagentFile)
	fmt.Printf("Cache TTL: %ds\n", cacheTTLSeconds)

	server := &http.Server{
		Addr:         ":" + port,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "Server failed: %v\n", err)
		os.Exit(1)
	}
}
