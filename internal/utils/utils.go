// internal/utils/utils.go
// Пакет utils содержит общие вспомогательные функции для обработки прокси-подписок.
// Все функции чистые и не зависят от глобального состояния.
package utils

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort" // <-- Импортируем sort
	"strconv"
	"strings"
)

// === Регулярные выражения ===
var (
	// hostRegex валидирует доменные имена (включая Punycode xn--)
	hostRegex = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$|^xn--([a-z0-9-]+\.)+[a-z0-9-]+$`)
	// ssCipherRe валидирует шифры Shadowsocks
	ssCipherRe = regexp.MustCompile(`^[a-zA-Z0-9_+-]+$`)
	// base64UrlRegex валидирует 32-байтный ключ в base64url без padding (43 символа)
	base64UrlRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// IsPrintableASCII проверяет, что байты содержат только печатаемые ASCII-символы.
// Допускает \n, \r, \t.
func IsPrintableASCII(data []byte) bool {
	for _, b := range data {
		if b >= 32 && b <= 126 {
			continue
		}
		// Сравниваем байт напрямую с его числовым значением
		// \n = 10, \r = 13, \t = 9
		if b == 10 || b == 13 || b == 9 { // '\n' || '\r' || '\t'
			continue
		}
		return false
	}
	return true
}

// AutoDecodeBase64 пытается декодировать весь входной буфер как base64.
// Если успешно и результат — печатаемый ASCII — возвращает декодированные байты.
// Иначе — возвращает исходные данные.
func AutoDecodeBase64(data []byte) []byte {
	// Удаляем все пробельные символы
	trimmed := regexp.MustCompile(`\s+`).ReplaceAll(data, []byte{})
	// Дополняем padding до кратности 4
	missingPadding := len(trimmed) % 4
	if missingPadding != 0 {
		trimmed = append(trimmed, bytes.Repeat([]byte{'='}, 4-missingPadding)...)
	}
	// Пробуем StdEncoding
	decoded, err := base64.StdEncoding.DecodeString(string(trimmed))
	if err != nil {
		// Пробуем RawStdEncoding
		decoded, err = base64.RawStdEncoding.DecodeString(string(trimmed))
		if err != nil {
			return data
		}
	}
	//if !IsPrintableASCII(decoded) {
	//	return data
	//}
	return decoded
}

// DecodeUserInfo безопасно декодирует base64-закодированный userinfo,
// определяя тип кодировки по наличию символов и padding.
func DecodeUserInfo(s string) ([]byte, error) {
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

// IsValidHost проверяет, что хост — это либо валидный домен,
// либо публичный IP-адрес.
func IsValidHost(host string) bool {
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true // IP всегда считается валидным здесь (фильтрация по типу — отдельно)
	}
	return hostRegex.MatchString(strings.ToLower(host))
}

// IsValidPort проверяет, что порт находится в диапазоне 1–65535.
func IsValidPort(port int) bool {
	return port > 0 && port <= 65535
}

// FullyDecode рекурсивно декодирует URL-encoded строки (например, %D0%9F → П).
func FullyDecode(s string) string {
	for {
		decoded, err := url.QueryUnescape(s)
		if err != nil || decoded == s {
			return s
		}
		s = decoded
	}
}

// ParseHostPort извлекает и валидирует хост и порт из *url.URL.
// Возвращает ошибку, если порт отсутствует, недействителен или хост невалиден.
func ParseHostPort(u *url.URL) (string, int, error) {
	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		return "", 0, fmt.Errorf("missing port")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port")
	}
	if !IsValidPort(port) {
		return "", 0, fmt.Errorf("port out of range")
	}
	if !IsValidHost(host) {
		return "", 0, fmt.Errorf("invalid host")
	}
	return host, port, nil
}

// IsPathSafe проверяет, что путь не выходит за пределы baseDir (защита от path traversal).
func IsPathSafe(p, baseDir string) bool {
	cleanPath := filepath.Clean(p)
	rel, err := filepath.Rel(baseDir, cleanPath)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."
}

// --- НОВЫЕ ФУНКЦИИ ДЛЯ /merge ---

// NormalizeLinkKey извлекает ключевые компоненты из URL-адреса прокси-ссылки для дедупликации.
// Игнорирует фрагментную часть (#...).
// Для протоколов, таких как VMess/SS, без значимых query-параметров, использует базовые компоненты.
// Теперь проводит базовую валидацию, чтобы убедиться, что входная строка - это правильно сформированный URL с хостом.
// ПАРАМЕТРЫ ЗАПРОСА СОРТИРУЮТСЯ ДЛЯ СТАБИЛЬНОГО КЛЮЧА.
// ПУСТОЙ ПУТЬ ИЛИ "/" ТЕПЕРЬ СЧИТАЮТСЯ РАВНОЗНАЧНЫМИ ДЛЯ ЦЕЛЕЙ КЛЮЧА.
// NormalizeLinkKey извлекает ключевые компоненты из URL-адреса прокси-ссылки для дедупликации.
// Игнорирует фрагментную часть (#...).
// ПУТИ "/" и "" считаются одинаковыми.
// ПОРТЫ ПО УМОЛЧАНИЮ (80/443) НЕ ВКЛЮЧАЮТСЯ В КЛЮЧ.
func NormalizeLinkKey(line string) (string, error) {
	u, err := url.Parse(line)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}
	if u.Scheme == "" {
		return "", fmt.Errorf("URL has no scheme")
	}
	if u.Host == "" {
		return "", fmt.Errorf("URL has no host")
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())

	// Определяем порт
	portStr := u.Port()
	if portStr == "" {
		// Присваиваем порт по умолчанию, но не будем включать его в ключ, если он стандартный
		if scheme == "https" {
			portStr = "443"
		} else if scheme == "http" {
			portStr = "80"
		}
		// Для других схем (vless, trojan и т.д.) порт ОБЯЗАТЕЛЕН → оставляем как есть, но он уже пуст → ошибка позже в process
		// Здесь же мы просто нормализуем ключ, поэтому если порт не указан — оставляем host без порта
	} else {
		// Порт указан явно → используем его
	}

	// Решаем, включать ли порт в ключ
	includePort := true
	if portStr != "" {
		if (scheme == "http" && portStr == "80") || (scheme == "https" && portStr == "443") {
			includePort = true
		}
	}

	var hostWithPort string
	if includePort && portStr != "" {
		hostWithPort = net.JoinHostPort(host, portStr)
	} else {
		hostWithPort = host
	}

	// Нормализуем путь
	path := u.Path
	if path == "/" {
		path = ""
	}

	// Сортируем query-параметры
	queryParams := make(map[string]string)
	q := u.Query()
	for k, vs := range q {
		if len(vs) > 0 {
			queryParams[k] = vs[0]
		}
	}
	var sortedKeys []string
	for k := range queryParams {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)
	var queryPart string
	if len(sortedKeys) > 0 {
		var parts []string
		for _, k := range sortedKeys {
			parts = append(parts, k+"="+queryParams[k])
		}
		queryPart = strings.Join(parts, "&")
	}

	key := fmt.Sprintf("%s://%s%s?%s", scheme, hostWithPort, path, queryPart)
	return key, nil
}

// CompareAndSelectBetter сравнивает две прокси-ссылки, которые считаются дубликатами по их ключу.
// Возвращает ту, которая считается "лучшей", как правило, более полную.
// Это простая эвристика: предпочитает ту, у которой больше query-параметров.
func CompareAndSelectBetter(currentLine, existingLine string) string {
	uCurrent, err1 := url.Parse(currentLine)
	uExisting, err2 := url.Parse(existingLine)

	// Если разбор не удался для одной, предпочитаем ту, что разобралась
	if err1 != nil {
		return existingLine
	}
	if err2 != nil {
		return currentLine
	}

	// Подсчитываем query-параметры
	currentParamCount := len(uCurrent.Query())
	existingParamCount := len(uExisting.Query())

	// Возвращаем ссылку с большим количеством параметров
	if currentParamCount > existingParamCount {
		return currentLine
	}
	if existingParamCount > currentParamCount {
		return existingLine
	}
	// Если количество равно, возвращаем существующую, чтобы сохранить стабильность
	return existingLine
}

// --- КОНЕЦ НОВЫХ ФУНКЦИЙ ---
