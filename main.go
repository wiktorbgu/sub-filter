// Пакет main — точка входа утилиты для фильтрации прокси-подписок.
//
// Поддерживает два режима работы:
//  1. HTTP-сервер: динамическая фильтрация по запросу /filter?id=1
//  2. CLI-режим: однократная обработка всех подписок и сохранение в кэш
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata"

	"sub-filter/hysteria2"
	"sub-filter/ss"
	"sub-filter/trojan"
	"sub-filter/vless"
	"sub-filter/vmess"

	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

// === Константы конфигурации ===

const (
	// Файлы конфигурации по умолчанию
	defaultSourcesFile  = "./config/sub.txt"    // Список URL подписок (по одному на строку)
	defaultBadWordsFile = "./config/bad.txt"    // Запрещённые слова (фильтрация по имени сервера)
	defaultUAgentFile   = "./config/uagent.txt" // Разрешённые User-Agent (для защиты от ботов)
	defaultCacheDir     = "./cache"             // Директория для хранения кэша

	// Ограничения на размеры данных
	maxIDLength       = 64       // Макс. длина ID источника (1..N или custom)
	maxURILength      = 4096     // Макс. длина одной строки подписки
	maxUserinfoLength = 1024     // Макс. длина userinfo (логин:пароль в URI)
	maxSourceBytes    = 10 << 20 // Макс. размер скачанной подписки (10 МБ)

	// Параметры rate limiting для защиты от флуда
	limiterBurst    = 5                      // Макс. запросов за раз
	limiterEvery    = 100 * time.Millisecond // Интервал пополнения "токенов"
	cleanupInterval = 2 * time.Minute        // Как часто чистить неактивные лимитёры
	inactiveTimeout = 30 * time.Minute       // Через сколько удалять неактивный лимитёр
)

// SafeSource — безопасный источник подписки с зарезолвленным публичным IP.
// Используется для предотвращения SSRF: фетч идёт только на этот IP.
type SafeSource struct {
	URL string // Исходный URL подписки
	IP  net.IP // Публичный IP, на который разрешено делать запрос
}

// SourceMap — карта источников: ID → безопасный источник.
type SourceMap map[string]*SafeSource

// === Глобальные переменные ===

var (
	// Конфигурация, задаваемая при запуске
	cfg *Config

	// Валидированные источники подписок (загружаются один раз)
	sources SourceMap

	// Списки для фильтрации
	badWords  []string // Запрещённые слова (нижний регистр)
	allowedUA []string // Разрешённые User-Agent (чувствительны к регистру)

	// Параметры кэширования
	cacheDir string        // Путь к директории кэша
	cacheTTL time.Duration // Время жизни кэша (в секундах)
)

// === Конфигурационная структура для удобства ===

type Config struct {
	CacheDir     string        // Директория кэша
	CacheTTL     time.Duration // TTL кэша
	SourcesFile  string        // Файл с источниками
	BadWordsFile string        // Файл с запрещёнными словами
	UAgentFile   string        // Файл с разрешёнными User-Agent
	Port         string        // Порт для HTTP-сервера
}

// === Регулярные выражения для валидации ===

var (
	// ID источника: латиница, цифры, подчёркивание
	validIDRe = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

	// Хост: домен (ASCII или Punycode) или IP
	hostRegex = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$|^xn--([a-z0-9-]+\.)+[a-z0-9-]+$`)
)

// === Rate limiting по IP ===

var (
	ipLimiter    = make(map[string]*rate.Limiter) // Лимитёры на IP
	ipLastSeen   = make(map[string]time.Time)     // Время последнего запроса с IP
	limiterMutex sync.RWMutex                     // Мьютекс для потокобезопасности
)

// === Глобальные компоненты ===

var (
	// fetchGroup предотвращает параллельные запросы к одному источнику
	fetchGroup singleflight.Group

	// Встроенные префиксы User-Agent, которые всегда разрешены
	builtinAllowedPrefixes = []string{"clash", "happ"}
)

// === Интерфейс обработчика протоколов ===

// ProxyLink — стандартный интерфейс для обработки ссылок на прокси.
// Позволяет легко добавлять поддержку новых протоколов.
type ProxyLink interface {
	// Matches проверяет, подходит ли строка под этот протокол
	Matches(s string) bool
	// Process обрабатывает строку и возвращает:
	//   - обработанную строку (если валидна)
	//   - причину отклонения (если невалидна)
	Process(s string) (string, string)
}

// Список всех поддерживаемых обработчиков (порядок не важен)
var proxyProcessors = []ProxyLink{
	vless.VLESSLink{},
	vmess.VMessLink{},
	trojan.TrojanLink{},
	ss.SSLink{},
	hysteria2.Hysteria2Link{},
}

// === Вспомогательные функции ===

// isPrintableASCII проверяет, что данные содержат только печатаемые символы.
// Используется для защиты от бинарных данных (например, случайный base64).
func isPrintableASCII(data []byte) bool {
	for _, b := range data {
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			return false
		}
	}
	return true
}

// autoDecodeBase64 пытается декодировать данные как base64.
// Если не получается — возвращает исходные данные.
func autoDecodeBase64(data []byte) []byte {
	trimmed := regexp.MustCompile(`\s+`).ReplaceAll(data, []byte{})
	missingPadding := len(trimmed) % 4
	if missingPadding != 0 {
		trimmed = append(trimmed, bytes.Repeat([]byte{'='}, 4-missingPadding)...)
	}
	if decoded, err := base64.StdEncoding.DecodeString(string(trimmed)); err == nil {
		if isPrintableASCII(decoded) {
			return decoded
		}
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(string(trimmed)); err == nil {
		if isPrintableASCII(decoded) {
			return decoded
		}
	}
	return data
}

// loadTextFile загружает текстовый файл, пропуская пустые строки и комментарии (#).
func loadTextFile(filename string, processor func(string) string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	// Пропустить BOM (UTF-8)
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

// getDefaultPort возвращает стандартный порт для http/https.
func getDefaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

// isValidSourceURL проверяет, что URL подписки безопасен для загрузки.
// Блокирует localhost, private IP, .local, .internal и другие опасные хосты.
func isValidSourceURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	// Разрешаем ТОЛЬКО http и https
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	// Явно блокируем локальные и специальные домены
	if host == "localhost" ||
		strings.HasPrefix(host, "127.") ||
		strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal") {
		return false
	}
	// IP-адреса проверяем отдельно
	if ip := net.ParseIP(host); ip != nil {
		return isIPAllowed(ip)
	}
	// Домены (включая Punycode) разрешены — валидация в hostRegex
	return true
}

// isIPAllowed проверяет, что IP — публичный и безопасный.
func isIPAllowed(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast())
}

// getLimiter возвращает или создаёт лимитёр для IP-адреса.
func getLimiter(ip string) *rate.Limiter {
	limiterMutex.Lock()
	defer limiterMutex.Unlock()
	ipLastSeen[ip] = time.Now()
	if limiter, exists := ipLimiter[ip]; exists {
		return limiter
	}
	limiter := rate.NewLimiter(rate.Every(limiterEvery), limiterBurst)
	ipLimiter[ip] = limiter
	return limiter
}

// cleanupLimiters — фоновая очистка неактивных лимитёров.
// Запускается в отдельной горутине и работает до завершения приложения.
func cleanupLimiters(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Сначала читаем под RLock
			limiterMutex.RLock()
			var toDelete []string
			now := time.Now()
			for ip, last := range ipLastSeen {
				if now.Sub(last) > inactiveTimeout {
					toDelete = append(toDelete, ip)
				}
			}
			limiterMutex.RUnlock()

			// Затем удаляем под Lock
			if len(toDelete) > 0 {
				limiterMutex.Lock()
				for _, ip := range toDelete {
					delete(ipLimiter, ip)
					delete(ipLastSeen, ip)
				}
				limiterMutex.Unlock()
			}
		}
	}
}

// isValidUserAgent проверяет, разрешён ли User-Agent.
func isValidUserAgent(ua string) bool {
	lowerUA := strings.ToLower(ua)
	// Встроенные префиксы
	for _, prefix := range builtinAllowedPrefixes {
		if strings.HasPrefix(lowerUA, prefix) {
			return true
		}
	}
	// Внешний список
	for _, allowed := range allowedUA {
		if allowed != "" && strings.Contains(lowerUA, strings.ToLower(allowed)) {
			return true
		}
	}
	return false
}

// isValidHost проверяет корректность хоста (домен или IP).
func isValidHost(host string) bool {
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true // IP всегда разрешён (публичность проверена ранее)
	}
	return hostRegex.MatchString(strings.ToLower(host))
}

// checkBadWordsInName проверяет, содержит ли название сервера запрещённые слова.
func checkBadWordsInName(fragment string) (bool, string) {
	if fragment == "" {
		return false, ""
	}
	decoded := fullyDecode(fragment)
	decodedLower := strings.ToLower(decoded)
	for _, word := range badWords {
		if word != "" && strings.Contains(decodedLower, word) {
			return true, fmt.Sprintf("bad word in name: %q", word)
		}
	}
	return false, ""
}

// fullyDecode рекурсивно декодирует URL-escape-последовательности.
func fullyDecode(s string) string {
	for {
		decoded, err := url.QueryUnescape(s)
		if err != nil || decoded == s {
			return s
		}
		s = decoded
	}
}

// isPathSafe защищает от path traversal (например, ../../etc/passwd).
func isPathSafe(p, baseDir string) bool {
	cleanPath := filepath.Clean(p)
	rel, err := filepath.Rel(baseDir, cleanPath)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."
}

// serveFile отдаёт подписку как файл для скачивания.
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

// isLocalIP проверяет, является ли IP локальным (loopback или private).
// Используется для исключения локальных запросов из rate limiting.
func isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true // недекодируемое — считаем локальным
	}
	// Нормализуем IPv4-mapped IPv6 (например, ::ffff:192.0.2.1 → 192.0.2.1)
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

// === Основная логика ===

// processSource обрабатывает одну подписку: скачивает, фильтрует, сохраняет.
func processSource(id string, source *SafeSource) error {
	parsedSource, err := url.Parse(source.URL)
	if err != nil || parsedSource.Host == "" {
		return fmt.Errorf("invalid source URL: %v", err)
	}
	host := parsedSource.Hostname()
	if !isValidHost(host) {
		return fmt.Errorf("invalid source host: %s", host)
	}

	// Пути к файлам кэша
	origCache := filepath.Join(cacheDir, "orig_"+id+".txt")
	modCache := filepath.Join(cacheDir, "mod_"+id+".txt")
	rejectedCache := filepath.Join(cacheDir, "rejected_"+id+".txt")

	// Защита от path traversal
	if !isPathSafe(origCache, cacheDir) ||
		!isPathSafe(modCache, cacheDir) ||
		!isPathSafe(rejectedCache, cacheDir) {
		return fmt.Errorf("unsafe cache path for id=%s", id)
	}

	// Если кэш актуален — выходим
	if info, err := os.Stat(modCache); err == nil && time.Since(info.ModTime()) <= cacheTTL {
		return nil
	}

	// Пытаемся использовать закэшированную исходную подписку
	var origContent []byte
	if info, err := os.Stat(origCache); err == nil && time.Since(info.ModTime()) <= cacheTTL {
		if content, err := os.ReadFile(origCache); err == nil {
			origContent = content
		}
	}

	// Если нет — скачиваем
	if origContent == nil {
		_, portStr, _ := net.SplitHostPort(parsedSource.Host)
		if portStr == "" {
			portStr = getDefaultPort(parsedSource.Scheme)
		}

		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					dialer := &net.Dialer{Timeout: 5 * time.Second}
					return dialer.DialContext(ctx, network, net.JoinHostPort(source.IP.String(), portStr))
				},
				TLSClientConfig: &tls.Config{ServerName: host},
				MaxIdleConns:    10,
				IdleConnTimeout: 30 * time.Second,
			},
		}

		result, err, _ := fetchGroup.Do(id, func() (interface{}, error) {
			req, err := http.NewRequest("GET", source.URL, nil)
			if err != nil {
				return nil, fmt.Errorf("create request: %w", err)
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

			// Сохраняем в .tmp, затем переименовываем (атомарно)
			tmpFile := origCache + ".tmp"
			if err := os.WriteFile(tmpFile, content, 0o644); err != nil {
				_ = os.Remove(tmpFile)
				return nil, fmt.Errorf("write orig cache: %w", err)
			}
			if err := os.Rename(tmpFile, origCache); err != nil {
				_ = os.Remove(tmpFile)
				return nil, fmt.Errorf("rename orig cache: %w", err)
			}
			return content, nil
		})
		if err != nil {
			return err
		}
		origContent = result.([]byte)
	}

	// Проверяем, нужно ли декодировать как base64
	hasProxy := bytes.Contains(origContent, []byte("vless://")) ||
		bytes.Contains(origContent, []byte("vmess://")) ||
		bytes.Contains(origContent, []byte("trojan://")) ||
		bytes.Contains(origContent, []byte("ss://")) ||
		bytes.Contains(origContent, []byte("hysteria2://")) ||
		bytes.Contains(origContent, []byte("hy2://"))
	if !hasProxy {
		decoded := autoDecodeBase64(origContent)
		if bytes.Contains(decoded, []byte("vless://")) ||
			bytes.Contains(decoded, []byte("vmess://")) ||
			bytes.Contains(decoded, []byte("trojan://")) ||
			bytes.Contains(decoded, []byte("ss://")) ||
			bytes.Contains(decoded, []byte("hysteria2://")) ||
			bytes.Contains(decoded, []byte("hy2://")) {
			origContent = decoded
		}
	}

	// Обрабатываем каждую строку
	var out []string
	var rejectedLines []string
	lines := bytes.Split(origContent, []byte("\n"))
	for _, lineBytes := range lines {
		originalLine := strings.TrimRight(string(lineBytes), "\r\n")
		if originalLine == "" || strings.HasPrefix(originalLine, "#") {
			continue
		}

		// Пробуем обработать через каждый обработчик
		var processedLine, reason string
		handled := false
		for _, p := range proxyProcessors {
			if p.Matches(originalLine) {
				processedLine, reason = p.Process(originalLine)
				handled = true
				break
			}
		}
		if !handled {
			reason = "unsupported protocol"
		}

		if processedLine != "" {
			out = append(out, processedLine)
		} else {
			if reason == "" {
				reason = "processing failed"
			}
			rejectedLines = append(rejectedLines, "# REASON: "+reason, originalLine)
		}
	}

	// Сохраняем отклонённые строки (если есть)
	if len(rejectedLines) > 0 {
		rejectedContent := strings.Join(rejectedLines, "\n")
		tmpFile := rejectedCache + ".tmp"
		if err := os.WriteFile(tmpFile, []byte(rejectedContent), 0o644); err != nil {
			_ = os.Remove(tmpFile)
		} else {
			_ = os.Rename(tmpFile, rejectedCache)
		}
	} else {
		_ = os.Remove(rejectedCache)
	}

	// Формируем итоговый файл подписки
	profileName := "filtered_" + id
	if u, err := url.Parse(source.URL); err == nil {
		base := path.Base(u.Path)
		if base != "" && regexp.MustCompile(`^[a-zA-Z0-9._-]+\.txt$`).MatchString(base) {
			profileName = strings.TrimSuffix(base, ".txt")
		}
	}
	profileName = regexp.MustCompile(`[^a-zA-Z0-9._-]`).ReplaceAllString(profileName, "_")
	updateInterval := int(cacheTTL.Seconds() / 3600)
	if updateInterval < 1 {
		updateInterval = 1
	}

	profileTitle := fmt.Sprintf("#profile-title: %s filtered %s", profileName, id)
	profileInterval := fmt.Sprintf("#profile-update-interval: %d", updateInterval)
	finalLines := []string{profileTitle, profileInterval, ""}
	finalLines = append(finalLines, out...)
	final := strings.Join(finalLines, "\n")

	tmpFile := modCache + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(final), 0o644); err != nil {
		_ = os.Remove(tmpFile)
		return err
	}
	_ = os.Rename(tmpFile, modCache)
	return nil
}

// handler — обработчик HTTP-запроса /filter?id=...
func handler(w http.ResponseWriter, r *http.Request) {
	// Определяем IP клиента
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}

	// Пропускаем локальные IP без лимитирования
	if !isLocalIP(clientIP) {
		limiter := getLimiter(clientIP)
		if !limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
	}

	// Проверяем User-Agent
	if !isValidUserAgent(r.Header.Get("User-Agent")) {
		http.Error(w, "Forbidden: invalid User-Agent", http.StatusForbidden)
		return
	}

	// Проверяем ID
	id := r.URL.Query().Get("id")
	if id == "" || len(id) > maxIDLength || !validIDRe.MatchString(id) {
		http.Error(w, "Invalid id", http.StatusBadRequest)
		return
	}

	// Проверяем, существует ли источник
	source, exists := sources[id]
	if !exists {
		http.Error(w, "Invalid id", http.StatusBadRequest)
		return
	}

	// Обрабатываем источник
	err = processSource(id, source)
	if err != nil {
		http.Error(w, fmt.Sprintf("Processing error: %v", err), http.StatusInternalServerError)
		return
	}

	// Отдаём результат
	content, err := os.ReadFile(filepath.Join(cacheDir, "mod_"+id+".txt"))
	if err != nil {
		http.Error(w, "Result not found", http.StatusNotFound)
		return
	}
	serveFile(w, r, content, source.URL, id)
}

// loadSources загружает и валидирует источники подписок.
func loadSources(sourcesFile string) (SourceMap, error) {
	lines, err := loadTextFile(sourcesFile, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load sources: %w", err)
	}
	sources := make(SourceMap)
	validIndex := 1
	for _, line := range lines {
		if !isValidSourceURL(line) {
			fmt.Fprintf(os.Stderr, "Skipping invalid or unsafe source URL: %s\n", line)
			continue
		}
		u, _ := url.Parse(line)
		host := u.Hostname()
		portStr := u.Port()
		if portStr == "" {
			portStr = getDefaultPort(u.Scheme)
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to resolve host %s: %v\n", host, err)
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
			fmt.Fprintf(os.Stderr, "No allowed public IP for host %s\n", host)
			continue
		}
		sources[strconv.Itoa(validIndex)] = &SafeSource{
			URL: line,
			IP:  allowedIP,
		}
		validIndex++
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("no valid sources loaded")
	}
	return sources, nil
}

// main — основная функция программы.
func main() {
	cliMode := flag.Bool("cli", false, "Run in CLI mode: process all sources once and exit")
	flag.Parse()

	cfg = &Config{
		CacheDir:     defaultCacheDir,
		CacheTTL:     1800 * time.Second,
		SourcesFile:  defaultSourcesFile,
		BadWordsFile: defaultBadWordsFile,
		UAgentFile:   defaultUAgentFile,
	}

	if *cliMode {
		// === CLI-режим ===
		args := flag.Args()
		if len(args) >= 1 {
			if sec, err := strconv.Atoi(args[0]); err == nil && sec > 0 {
				cfg.CacheTTL = time.Duration(sec) * time.Second
			}
		}
		if len(args) >= 2 {
			cfg.SourcesFile = args[1]
		}
		if len(args) >= 3 {
			cfg.BadWordsFile = args[2]
		}
		if len(args) >= 4 {
			cfg.UAgentFile = args[3]
		}

		cacheDir = cfg.CacheDir
		cacheTTL = cfg.CacheTTL
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "Cannot create cache dir: %v\n", err)
			os.Exit(1)
		}

		var err error
		sources, err = loadSources(cfg.SourcesFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v. Exiting.\n", err)
			os.Exit(1)
		}
		badWords, err = loadTextFile(cfg.BadWordsFile, strings.ToLower)
		if err != nil {
			badWords = []string{}
		}
		allowedUA, err = loadTextFile(cfg.UAgentFile, nil)
		if err != nil {
			allowedUA = []string{}
		}

		// Инициализация парсеров
		vless.SetGlobals(badWords, isValidHost, isValidPort, checkBadWordsInName)
		vmess.SetGlobals(badWords, isValidHost, checkBadWordsInName)
		trojan.SetGlobals(badWords, isValidHost, checkBadWordsInName)
		ss.SetGlobals(badWords, isValidHost, checkBadWordsInName)
		hysteria2.SetGlobals(badWords, isValidHost, checkBadWordsInName)

		fmt.Printf("Processing %d sources\n", len(sources))
		for id, source := range sources {
			fmt.Printf("Processing %s\n", id)
			if err := processSource(id, source); err != nil {
				fmt.Fprintf(os.Stderr, "Error %s: %v\n", id, err)
			}
		}
		fmt.Println("Done.")
		return
	}

	// === Серверный режим ===
	if len(flag.Args()) < 1 {
		fmt.Fprintf(os.Stderr, "Usage (server): %s <port> [cache_ttl] [sources] [bad] [ua]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Usage (CLI): %s --cli [cache_ttl] [sources] [bad] [ua]\n", os.Args[0])
		os.Exit(1)
	}

	cfg.Port = flag.Args()[0]
	if len(flag.Args()) >= 2 {
		if sec, err := strconv.Atoi(flag.Args()[1]); err == nil && sec > 0 {
			cfg.CacheTTL = time.Duration(sec) * time.Second
		}
	}
	if len(flag.Args()) >= 3 {
		cfg.SourcesFile = flag.Args()[2]
	}
	if len(flag.Args()) >= 4 {
		cfg.BadWordsFile = flag.Args()[3]
	}
	if len(flag.Args()) >= 5 {
		cfg.UAgentFile = flag.Args()[4]
	}

	cacheDir = cfg.CacheDir
	cacheTTL = cfg.CacheTTL
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot create cache dir: %v\n", err)
		os.Exit(1)
	}

	var err error
	sources, err = loadSources(cfg.SourcesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v. Exiting.\n", err)
		os.Exit(1)
	}
	badWords, err = loadTextFile(cfg.BadWordsFile, strings.ToLower)
	if err != nil {
		badWords = []string{}
	}
	allowedUA, err = loadTextFile(cfg.UAgentFile, nil)
	if err != nil {
		allowedUA = []string{}
	}

	// Инициализация парсеров
	vless.SetGlobals(badWords, isValidHost, isValidPort, checkBadWordsInName)
	vmess.SetGlobals(badWords, isValidHost, checkBadWordsInName)
	trojan.SetGlobals(badWords, isValidHost, checkBadWordsInName)
	ss.SetGlobals(badWords, isValidHost, checkBadWordsInName)
	hysteria2.SetGlobals(badWords, isValidHost, checkBadWordsInName)

	// Запуск фоновой очистки лимитёров
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go cleanupLimiters(ctx)

	// HTTP-обработчик
	http.HandleFunc("/filter", handler)

	// Слушаем порт
	listener, err := net.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Listen failed: %v\n", err)
		os.Exit(1)
	}

	server := &http.Server{
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	// Запуск сервера в фоне
	errChan := make(chan error, 1)
	go func() {
		fmt.Printf("Server listening on :%s\n", cfg.Port)
		errChan <- server.Serve(listener)
	}()

	// Ожидание сигнала завершения
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errChan:
		fmt.Fprintf(os.Stderr, "Server failed: %v\n", err)
		os.Exit(1)
	case <-sigChan:
		fmt.Println("\nShutting down gracefully...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "Force shutdown: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Println("Server stopped.")
}

// isValidPort проверяет, что порт в диапазоне 1–65535.
func isValidPort(port int) bool {
	return port > 0 && port <= 65535
}
