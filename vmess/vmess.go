// Пакет vmess — обработчик ссылок VMess (base64-encoded JSON).
// Проверяет наличие TLS, валидность UUID, фильтрует по bad-words.
package vmess

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
)

var (
	badWords      []string
	isValidHost   func(string) bool
	checkBadWords func(string) (bool, string)
)

// VMessLink — реализация интерфейса ProxyLink для VMess.
type VMessLink struct{}

// SetGlobals внедряет зависимости.
func SetGlobals(bw []string, vh func(string) bool, cb func(string) (bool, string)) {
	badWords = bw
	isValidHost = vh
	checkBadWords = cb
}

// Matches проверяет префикс vmess://.
func (VMessLink) Matches(s string) bool {
	return strings.HasPrefix(strings.ToLower(s), "vmess://")
}

// Process обрабатывает VMess-ссылку.
func (VMessLink) Process(s string) (string, string) {
	const maxURILength = 4096
	if len(s) > maxURILength {
		return "", "line too long"
	}
	if !strings.HasPrefix(strings.ToLower(s), "vmess://") {
		return "", "not a VMess link"
	}
	b64 := strings.TrimPrefix(s, "vmess://")
	if b64 == "" {
		return "", "empty VMess payload"
	}
	decoded, err := decodeUserInfo(b64)
	if err != nil {
		return "", "invalid VMess base64 encoding"
	}
	var vm map[string]interface{}
	if err := json.Unmarshal(decoded, &vm); err != nil {
		return "", "invalid VMess JSON format"
	}
	ps, _ := vm["ps"].(string)
	add, _ := vm["add"].(string)
	var port float64
	switch v := vm["port"].(type) {
	case float64:
		port = v
	case string:
		if p, err := strconv.ParseFloat(v, 64); err == nil {
			port = p
		} else {
			return "", "invalid port in VMess config"
		}
	default:
		return "", "missing or invalid port in VMess config"
	}
	id, _ := vm["id"].(string)
	if add == "" || id == "" {
		return "", "missing server address or UUID"
	}
	if int(port) <= 0 || int(port) > 65535 {
		return "", "invalid port number"
	}
	if !isValidHost(add) {
		return "", "invalid server host"
	}
	if ps != "" {
		if hasBad, reason := checkBadWords(ps); hasBad {
			return "", reason
		}
	}
	netType, _ := vm["net"].(string)
	if netType == "grpc" {
		svc, _ := vm["serviceName"].(string)
		if svc == "" {
			return "", "VMess gRPC requires serviceName"
		}
	}
	tls, _ := vm["tls"].(string)
	if netType != "grpc" && tls != "tls" {
		return "", "VMess without TLS is not allowed"
	}
	reencoded, err := json.Marshal(vm)
	if err != nil {
		return "", "failed to re-encode VMess config"
	}
	finalB64 := base64.StdEncoding.EncodeToString(reencoded)
	return "vmess://" + finalB64, ""
}

// Универсальный декодер base64 (STD/URL-safe, padded/raw).
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
