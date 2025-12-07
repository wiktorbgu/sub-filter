// Пакет ss — обработчик ссылок Shadowsocks.
// Проверяет шифр, пароль, хост, фильтрует по bad-words.
package ss

import (
	"encoding/base64"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	badWords      []string
	isValidHost   func(string) bool
	checkBadWords func(string) (bool, string)
	ssCipherRe    = regexp.MustCompile(`^[a-zA-Z0-9_+-]+$`) // Валидный шифр
)

// SSLink — реализация интерфейса ProxyLink для Shadowsocks.
type SSLink struct{}

// SetGlobals внедряет зависимости.
func SetGlobals(bw []string, vh func(string) bool, cb func(string) (bool, string)) {
	badWords = bw
	isValidHost = vh
	checkBadWords = cb
}

// Matches проверяет префикс ss://.
func (SSLink) Matches(s string) bool {
	return strings.HasPrefix(strings.ToLower(s), "ss://")
}

// Process обрабатывает Shadowsocks-ссылку.
func (SSLink) Process(s string) (string, string) {
	const maxURILength = 4096
	const maxUserinfoLength = 1024
	if len(s) > maxURILength {
		return "", "line too long"
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "ss" {
		return "", "invalid Shadowsocks URL format"
	}
	userinfo := u.User.String()
	if userinfo == "" || len(userinfo) > maxUserinfoLength {
		return "", "missing or too long userinfo"
	}
	decoded, err := decodeUserInfo(userinfo)
	if err != nil {
		return "", "invalid Shadowsocks base64 encoding"
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "invalid cipher:password format"
	}
	cipher, password := parts[0], parts[1]
	if cipher == "" || password == "" || !ssCipherRe.MatchString(cipher) {
		return "", "invalid cipher or password"
	}
	host, port, ok := parseHostPort(u)
	if !ok {
		return "", "invalid host or port"
	}
	if hasBad, reason := checkBadWords(u.Fragment); hasBad {
		return "", reason
	}
	newUser := base64.RawURLEncoding.EncodeToString([]byte(cipher + ":" + password))
	var buf strings.Builder
	buf.WriteString("ss://")
	buf.WriteString(newUser)
	buf.WriteString("@")
	buf.WriteString(net.JoinHostPort(host, strconv.Itoa(port)))
	if u.Fragment != "" {
		buf.WriteString("#")
		buf.WriteString(u.Fragment)
	}
	return buf.String(), ""
}

// Универсальный декодер base64 (как в VMess).
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

// Парсинг хоста и порта.
func parseHostPort(u *url.URL) (string, int, bool) {
	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		return "", 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 || !isValidHost(host) {
		return "", 0, false
	}
	return host, port, true
}
