// Пакет main реализует утилиту для фильтрации прокси-подписок.
// Поддерживает два режима работы:
//   - HTTP-сервер для динамической фильтрации (/filter?id=1)
//   - CLI-режим для однократной обработки всех подписок (--cli)
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
// Примечание: defaultCacheDir НЕ может быть константой, так как зависит от os.TempDir().
const (
	// Файлы конфигурации по умолчанию
	defaultSourcesFile  = "./config/sub.txt"    // Файл со списком URL подписок
	defaultBadWordsFile = "./config/bad.txt"    // Файл с запрещёнными словами
	defaultUAgentFile   = "./config/uagent.txt" // Файл с разрешёнными User-Agent
	// defaultCacheDir определён ниже как переменная
	// Ограничения на размеры данных
	maxIDLength       = 64               // Макс. длина идентификатора источника
	maxURILength      = 4096             // Макс. длина одной строки подписки
	maxUserinfoLength = 1024             // Макс. длина userinfo в URI
	maxSourceBytes    = 10 * 1024 * 1024 // Макс. размер скачиваемой подписки (10 МБ)
	// Параметры rate limiting
	limiterBurst    = 5                      // Макс. число запросов за раз
	limiterEvery    = 100 * time.Millisecond // Интервал пополнения лимита
	cleanupInterval = 2 * time.Minute        // Интервал очистки старых лимитёров
	inactiveTimeout = 30 * time.Minute       // Время неактивности для удаления лимитёра
)

// === Переменная: временная директория по умолчанию ===
// Используем os.TempDir() для совместимости с distroless nonroot контейнерами,
// где /tmp — единственное место, доступное для записи.
var defaultCacheDir = filepath.Join(os.TempDir(), "sub-filter-cache")

// SafeSource представляет проверенный источник подписки с зарезолвленным публичным IP.
type SafeSource struct {
	URL string // Исходный URL подписки
	IP  net.IP // Публичный IP, на который будет выполнен фетч
}

// SourceMap — карта источников, где ключ — строковый ID (1, 2, 3...).
type SourceMap map[string]*SafeSource

// === Глобальные переменные конфигурации ===
var (
	cacheDir  string        // Директория кэша (устанавливается при запуске)
	cacheTTL  time.Duration // Время жизни кэша
	sources   SourceMap     // Валидированные источники подписок
	badWords  []string      // Список запрещённых слов для фильтрации
	allowedUA []string      // Список разрешённых User-Agent
)

// === Регулярные выражения для валидации ===
var (
	validIDRe = regexp.MustCompile(`^[a-zA-Z0-9_]+$`) // Валидный ID источника
	// Валидный домен: ASCII или Punycode (xn--)
	hostRegex = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$|^xn--([a-z0-9-]+\.)+[a-z0-9-]+$`)
)

// === Rate limiting по IP-адресам ===
var (
	ipLimiter    = make(map[string]*rate.Limiter) // Лимитёры по IP
	ipLastSeen   = make(map[string]time.Time)     // Последнее обращение по IP
	limiterMutex sync.RWMutex                     // Мьютекс для безопасного доступа
)

// === HTTP-фетчер с дедупликацией ===
// fetchGroup используется для предотвращения параллельных фетчей одного источника.
var fetchGroup singleflight.Group

// Встроенные разрешённые User-Agent-префиксы.
var builtinAllowedPrefixes = []string{"clash", "happ"}

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

// isPrintableASCII проверяет, что байты содержат только печатаемые ASCII-символы.
func isPrintableASCII(data []byte) bool {
	for _, b := range data {
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			return false
		}
	}
	return true
}

// autoDecodeBase64 пытается декодировать весь входной буфер как base64.
// Если успешно — возвращает декодированные байты, иначе — исходные.
func autoDecodeBase64(data []byte) []byte {
	// Удаляем все пробельные символы (включая \n, \r, пробелы)
	trimmed := regexp.MustCompile(`\s+`).ReplaceAll(data, []byte{})
	// Дополняем padding до кратности 4
	missingPadding := len(trimmed) % 4
	if missingPadding != 0 {
		trimmed = append(trimmed, bytes.Repeat([]byte{'='}, 4-missingPadding)...)
	}
	// Пробуем декодировать
	decoded, err := base64.StdEncoding.DecodeString(string(trimmed))
	if err != nil {
		// Пробуем Raw-кодировку (без padding)
		decoded, err = base64.RawStdEncoding.DecodeString(string(trimmed))
		if err != nil {
			return data // не base64
		}
	}
	// Проверяем, что декодированное содержимое — текст (а не бинарник)
	if !isPrintableASCII(decoded) {
		return data
	}
	return decoded
}

// LineProcessor — тип функции для обработки строк при загрузке файлов.
type LineProcessor func(string) string

// loadTextFile загружает текстовый файл, пропуская пустые строки и комментарии.
// Применяет опциональный процессор к каждой строке.
func loadTextFile(filename string, processor LineProcessor) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	// Пропускаем BOM, если есть
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

// getDefaultPort возвращает стандартный порт для схемы.
func getDefaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

// isValidSourceURL проверяет, что URL подписки безопасен для фетча.
// Запрещает localhost, приватные IP, loopback и специальные домены.
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
	// Punycode (xn--) разрешён — валидация в isValidHost через hostRegex
	if ip := net.ParseIP(host); ip != nil {
		// Используем централизованную проверку IP
		return isIPAllowed(ip)
	}
	return true
}

// isIPAllowed проверяет, что IP-адрес является публичным и пригодным для фетча.
func isIPAllowed(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast())
}

// getLimiter возвращает или создаёт rate.Limiter для IP-адреса.
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

// cleanupLimiters запускает фоновую горутину для удаления неактивных лимитёров.
func cleanupLimiters(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			limiterMutex.RLock()
			var toDelete []string
			now := time.Now()
			for ip, last := range ipLastSeen {
				if now.Sub(last) > inactiveTimeout {
					toDelete = append(toDelete, ip)
				}
			}
			limiterMutex.RUnlock()

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

// isValidUserAgent проверяет, что User-Agent разрешён.
// Поддерживает встроенные префиксы и внешний список.
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

// isValidHost проверяет корректность хоста (домен или публичный IP).
// Поддерживает Punycode (xn--).
func isValidHost(host string) bool {
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	return hostRegex.MatchString(strings.ToLower(host))
}

// isValidPort проверяет, что порт в допустимом диапазоне.
func isValidPort(port int) bool {
	return port > 0 && port <= 65535
}

// fullyDecode рекурсивно декодирует URL-escape-последовательности.
// Используется для проверки запрещённых слов в названиях.
func fullyDecode(s string) string {
	for {
		decoded, err := url.QueryUnescape(s)
		if err != nil || decoded == s {
			return s
		}
		s = decoded
	}
}

// checkBadWordsInName проверяет, содержит ли fragment (название сервера) запрещённые слова.
// Возвращает true и детализированную причину, если найдено.
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

// isPathSafe проверяет, что путь находится внутри базовой директории (защита от path traversal).
func isPathSafe(p, baseDir string) bool {
	cleanPath := filepath.Clean(p)
	rel, err := filepath.Rel(baseDir, cleanPath)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."
}

// serveFile отдаёт подписку как attachment с правильным Content-Disposition.
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

// isLocalIP проверяет, является ли IP-адрес локальным (loopback или private).
// Используется для исключения из rate limiting.
func isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true // недекодируемое — считаем локальным (консервативно)
	}
	// Нормализуем IPv4-mapped IPv6 для корректной проверки
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

// === Основная логика ===

// processSource обрабатывает одну подписку и сохраняет результат в кэш.
// Используется как в HTTP-обработчике, так и в CLI-режиме.
// Использует fetchGroup для дедупликации параллельных фетчей одного источника.
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
	if !isPathSafe(origCache, cacheDir) || !isPathSafe(modCache, cacheDir) || !isPathSafe(rejectedCache, cacheDir) {
		return fmt.Errorf("unsafe cache path for id=%s", id)
	}
	// Если уже обработано и не устарело — ничего не делаем
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
				TLSClientConfig: &tls.Config{
					ServerName: host,
				},
				MaxIdleConns:    10,
				IdleConnTimeout: 30 * time.Second,
			},
		}
		// Используем fetchGroup для дедупликации фетчей
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
			// Сохраняем исходную подписку в кэш с атомарным rename
			tmpFile := origCache + ".tmp"
			if writeErr := os.WriteFile(tmpFile, content, 0o644); writeErr != nil {
				_ = os.Remove(tmpFile)
				return nil, fmt.Errorf("write orig cache: %w", writeErr)
			}
			if renameErr := os.Rename(tmpFile, origCache); renameErr != nil {
				_ = os.Remove(tmpFile)
				return nil, fmt.Errorf("rename orig cache: %w", renameErr)
			}
			return content, nil
		})
		if err != nil {
			return err
		}
		origContent = result.([]byte)
	}
	// === ОПРЕДЕЛЯЕМ: base64 или нет? ===
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
	// ===================================
	// Обработка строк подписки с детализацией причин
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
			// Если reason пуст (маловероятно), укажем общую ошибку
			if reason == "" {
				reason = "processing failed"
			}
			rejectedLines = append(rejectedLines, "# REASON: "+reason, originalLine)
		}
	}
	// Сохраняем rejected-файл или удаляем, если пуст
	if len(rejectedLines) > 0 {
		rejectedContent := strings.Join(rejectedLines, "\n")
		tmpRejectedFile := rejectedCache + ".tmp"
		if err := os.WriteFile(tmpRejectedFile, []byte(rejectedContent), 0o644); err == nil {
			_ = os.Rename(tmpRejectedFile, rejectedCache)
		} else {
			_ = os.Remove(tmpRejectedFile)
		}
	} else {
		_ = os.Remove(rejectedCache) // Игнорируем ошибку "файл не найден"
	}
	// Формируем имя для profile-title
	profileName := "filtered_" + id
	if u, err := url.Parse(source.URL); err == nil {
		base := path.Base(u.Path)
		if base != "" && regexp.MustCompile(`^[a-zA-Z0-9._-]+\.txt$`).MatchString(base) {
			profileName = strings.TrimSuffix(base, ".txt")
		}
	}
	profileName = regexp.MustCompile(`[^a-zA-Z0-9._-]`).ReplaceAllString(profileName, "_")
	// Обеспечиваем updateInterval >= 1
	updateInterval := int(cacheTTL.Seconds() / 3600)
	if updateInterval < 1 {
		updateInterval = 1
	}
	profileTitle := fmt.Sprintf("#profile-title: %s filtered %s", profileName, id)
	profileInterval := fmt.Sprintf("#profile-update-interval: %d", updateInterval)
	finalLines := []string{profileTitle, profileInterval, ""}
	finalLines = append(finalLines, out...)
	final := strings.Join(finalLines, "\n")
	// Сохраняем итоговый файл с атомарным rename
	tmpFile := modCache + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(final), 0o644); err != nil {
		_ = os.Remove(tmpFile)
		return err
	}
	_ = os.Rename(tmpFile, modCache)
	return nil
}

// handler обрабатывает HTTP-запрос /filter?id=...
func handler(w http.ResponseWriter, r *http.Request) {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}
	// Пропускаем лимитирование для локальных IP (127.0.0.1, ::1, 192.168.x.x, fd00::/8 и т.д.)
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
// Возвращает SourceMap и ошибку.
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

// main — точка входа программы с поддержкой двух режимов.
func main() {
	cliMode := flag.Bool("cli", false, "Run in CLI mode: process all sources once and exit")
	flag.Parse()

	if *cliMode {
		// === CLI-режим: обработать все подписки один раз и выйти ===
		cacheTTLSeconds := 1800
		sourcesFile := defaultSourcesFile
		badWordsFile := defaultBadWordsFile
		uagentFile := defaultUAgentFile
		args := flag.Args()
		if len(args) >= 1 {
			if sec, err := strconv.Atoi(args[0]); err == nil && sec > 0 {
				cacheTTLSeconds = sec
			}
		}
		if len(args) >= 2 {
			sourcesFile = args[1]
		}
		if len(args) >= 3 {
			badWordsFile = args[2]
		}
		if len(args) >= 4 {
			uagentFile = args[3]
		}
		cacheTTL = time.Duration(cacheTTLSeconds) * time.Second
		cacheDir = defaultCacheDir
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "Cannot create cache dir: %v\n", err)
			os.Exit(1)
		}

		// Загрузка источников
		var err error
		sources, err = loadSources(sourcesFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v. Exiting.\n", err)
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

		// Инициализация зависимостей парсеров
		vless.SetGlobals(badWords, isValidHost, isValidPort, checkBadWordsInName)
		vmess.SetGlobals(badWords, isValidHost, checkBadWordsInName)
		trojan.SetGlobals(badWords, isValidHost, checkBadWordsInName)
		ss.SetGlobals(badWords, isValidHost, checkBadWordsInName)
		hysteria2.SetGlobals(badWords, isValidHost, checkBadWordsInName)

		fmt.Printf("CLI mode: processing %d sources\n", len(sources))
		fmt.Printf("Cache TTL: %d seconds\n", cacheTTLSeconds)
		fmt.Printf("Cache directory: %s\n", cacheDir)
		for id, source := range sources {
			fmt.Printf("Processing source %s: %s\n", id, source.URL)
			if err := processSource(id, source); err != nil {
				fmt.Fprintf(os.Stderr, "Failed source %s: %v\n", id, err)
			} else {
				fmt.Printf("Success: mod_%s.txt saved\n", id)
			}
		}
		fmt.Println("Done.")
		return
	}

	// === Серверный режим: запуск HTTP-сервера ===
	if len(flag.Args()) < 1 {
		fmt.Fprintf(os.Stderr, "Usage (server mode): %s <port> [cache_ttl_seconds] [sources_file] [bad_words_file] [uagent_file]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Usage (CLI mode): %s --cli [cache_ttl_seconds] [sources_file] [bad_words_file] [uagent_file]\n", os.Args[0])
		os.Exit(1)
	}

	port := flag.Args()[0]
	cacheTTLSeconds := 1800
	if len(flag.Args()) >= 2 {
		if sec, err := strconv.Atoi(flag.Args()[1]); err == nil && sec > 0 {
			cacheTTLSeconds = sec
		}
	}
	sourcesFile := defaultSourcesFile
	if len(flag.Args()) >= 3 {
		sourcesFile = flag.Args()[2]
	}
	badWordsFile := defaultBadWordsFile
	if len(flag.Args()) >= 4 {
		badWordsFile = flag.Args()[3]
	}
	uagentFile := defaultUAgentFile
	if len(flag.Args()) >= 5 {
		uagentFile = flag.Args()[4]
	}
	cacheTTL = time.Duration(cacheTTLSeconds) * time.Second
	cacheDir = defaultCacheDir
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot create cache dir: %v\n", err)
		os.Exit(1)
	}

	// Загрузка источников
	var err error
	sources, err = loadSources(sourcesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v. Exiting.\n", err)
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

	// Инициализация зависимостей парсеров
	vless.SetGlobals(badWords, isValidHost, isValidPort, checkBadWordsInName)
	vmess.SetGlobals(badWords, isValidHost, checkBadWordsInName)
	trojan.SetGlobals(badWords, isValidHost, checkBadWordsInName)
	ss.SetGlobals(badWords, isValidHost, checkBadWordsInName)
	hysteria2.SetGlobals(badWords, isValidHost, checkBadWordsInName)

	// Запуск фоновой очистки лимитёров
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go cleanupLimiters(ctx)

	http.HandleFunc("/filter", handler)

	// IPv6-ready запуск сервера: слушает и IPv4, и IPv6
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot listen on port %s: %v\n", port, err)
		os.Exit(1)
	}

	// === ВЫВОД ПАРАМЕТРОВ ПРИ СТАРТЕ ===
	fmt.Printf("Proxy Filter Server Starting...\n")
	fmt.Printf("Listening on port: %s\n", port)
	fmt.Printf("Cache TTL: %d seconds\n", cacheTTLSeconds)
	fmt.Printf("Cache directory: %s\n", cacheDir)
	fmt.Printf("Valid sources loaded: %d\n", len(sources))
	fmt.Printf("Bad words file: %s\n", badWordsFile)
	fmt.Printf("User-Agent file: %s\n", uagentFile)
	fmt.Println("Server is ready.")
	// ===================================

	server := &http.Server{
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	// Graceful shutdown
	errChan := make(chan error, 1)
	go func() {
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
