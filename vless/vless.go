// Package vless обрабатывает VLESS-ссылки (vless://).
package vless

import (
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"sub-filter/internal/validator"
)

// VLESSLink реализует обработку VLESS-ссылок.
type VLESSLink struct {
	badWords       []string
	isValidHost    func(string) bool
	isValidPort    func(int) bool
	checkBadWords  func(string) (bool, string)
	ruleValidator  validator.Validator
	hostRegex      *regexp.Regexp
	base64UrlRegex *regexp.Regexp
}

// NewVLESSLink создаёт новый обработчик VLESS.
// Принимает валидатор политик — если nil, используется пустой GenericValidator.
func NewVLESSLink(
	bw []string,
	vh func(string) bool,
	vp func(int) bool,
	cb func(string) (bool, string),
	val validator.Validator,
) *VLESSLink {
	if val == nil {
		val = &validator.GenericValidator{}
	}
	return &VLESSLink{
		badWords:       bw,
		isValidHost:    vh,
		isValidPort:    vp,
		checkBadWords:  cb,
		ruleValidator:  val,
		hostRegex:      regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?$|^xn--([a-z0-9-]+\.)+[a-z0-9-]+$`),
		base64UrlRegex: regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`),
	}
}

// Matches проверяет, является ли строка VLESS-ссылкой.
func (v *VLESSLink) Matches(s string) bool {
	return strings.HasPrefix(strings.ToLower(s), "vless://")
}

// Process парсит, валидирует и нормализует VLESS-ссылку.
func (v *VLESSLink) Process(s string) (string, string) {
	const maxURILength = 4096
	const maxIDLength = 64
	if len(s) > maxURILength {
		return "", "line too long"
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "vless" {
		return "", "invalid VLESS URL format"
	}
	uuid := u.User.Username()
	if uuid == "" || len(uuid) > maxIDLength {
		return "", "missing or invalid UUID"
	}
	host, port, hostErr := v.validateVLESSHostPort(u)
	if hostErr != "" {
		return "", "VLESS: " + hostErr
	}
	if hasBad, reason := v.checkBadWords(u.Fragment); hasBad {
		return "", reason
	}

	q := u.Query()
	q.Del("insecure")
	q.Del("allowInsecure")

	// 🔥 УДАЛЕНО: требование параметра `encryption`
	// Теперь это регулируется политикой (если нужно)

	// Собираем параметры для валидатора
	params := make(map[string]string, len(q))
	for k, vs := range q {
		if len(vs) > 0 {
			params[k] = vs[0]
		}
	}

	// --- НОВАЯ ЛОГИКА: Установка значения по умолчанию для 'type' ---
	// Если параметр 'type' отсутствует в URL, устанавливаем его в "raw" (синоним "tcp").
	// Это позволяет политике из rules.yaml корректно обрабатывать отсутствие type как type=raw.
	//if _, exists := params["type"]; !exists {
	//	params["type"] = "tcp"
	//}
	// --- КОНЕЦ НОВОЙ ЛОГИКИ ---

	// --- НОВАЯ ЛОГИКА ---
	// Если параметр 'security' отсутствует в URL, добавляем его со значением 'none'
	// Это позволяет политике из rules.yaml корректно обрабатывать отсутствие security
	if _, exists := params["security"]; !exists {
		params["security"] = "none"
	}
	// --- КОНЕЦ НОВОЙ ЛОГИКИ ---

	// Валидация теперь полностью делегирована политике
	if result := v.ruleValidator.Validate(params); !result.Valid {
		return "", "VLESS: " + result.Reason
	}

	// Обработка ALPN (остаётся как часть форматирования, а не валидации)
	if alpnValues := q["alpn"]; len(alpnValues) > 0 {
		rawAlpn := alpnValues[0]
		var firstValid string
		if strings.HasPrefix(rawAlpn, "h3") {
			firstValid = "h3"
		} else if strings.HasPrefix(rawAlpn, "h2") {
			firstValid = "h2"
		} else if strings.HasPrefix(rawAlpn, "http/1.1") {
			firstValid = "http/1.1"
		} else {
			if idx := strings.IndexByte(rawAlpn, ','); idx != -1 {
				firstValid = rawAlpn[:idx]
			} else {
				firstValid = rawAlpn
			}
		}
		if firstValid != "" {
			q["alpn"] = []string{firstValid}
		} else {
			delete(q, "alpn")
		}
	}

	var buf strings.Builder
	buf.WriteString("vless://")
	buf.WriteString(uuid)
	buf.WriteString("@")
	buf.WriteString(net.JoinHostPort(host, strconv.Itoa(port)))
	if u.Path != "" {
		buf.WriteString(u.Path)
	}
	if len(q) > 0 {
		buf.WriteString("?")
		buf.WriteString(q.Encode())
	}
	if u.Fragment != "" {
		buf.WriteString("#")
		buf.WriteString(u.Fragment)
	}
	return buf.String(), ""
}

// validateVLESSHostPort извлекает и проверяет хост и порт.
func (v *VLESSLink) validateVLESSHostPort(u *url.URL) (string, int, string) {
	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		return "", 0, "missing port"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, "invalid port"
	}
	if !v.isValidPort(port) {
		return "", 0, "port out of range"
	}
	if !v.isValidHost(host) {
		return "", 0, "invalid host"
	}
	return host, port, ""
}
