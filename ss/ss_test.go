package ss

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"sub-filter/internal/utils"
	"sub-filter/internal/validator"
)

func loadRuleForTest(proto string) validator.Validator {
	rules := map[string]validator.Rule{
		"hysteria2": {
			RequiredParams: []string{"obfs", "obfs-password"},
			AllowedValues: map[string][]string{
				"obfs": {"salamander"},
			},
		},
		"vless": {
			RequiredParams: []string{"encryption", "sni"},
			ForbiddenValues: map[string][]string{
				"security": {"none"},
			},
			AllowedValues: map[string][]string{
				"security": {"tls", "reality"},
			},
			Conditional: []validator.Condition{
				{When: map[string]string{"security": "reality"}, Require: []string{"pbk"}},
				{When: map[string]string{"type": "grpc"}, Require: []string{"serviceName"}},
				{When: map[string]string{"type": "ws"}, Require: []string{"path"}},
			},
		},
		"vmess": {
			RequiredParams: []string{"tls"},
			AllowedValues: map[string][]string{
				"tls": {"tls"},
			},
		},
		"trojan": {
			ForbiddenValues: map[string][]string{
				"flow": {"*"},
			},
			Conditional: []validator.Condition{
				{When: map[string]string{"type": "grpc"}, Require: []string{"serviceName"}},
			},
		},
		"ss": {
			ForbiddenValues: map[string][]string{
				"method": {"aes-128-cfb", "aes-256-cfb", "aes-128-ctr", "aes-256-ctr"},
			},
		},
	}
	if rule, ok := rules[proto]; ok {
		return &validator.GenericValidator{Rule: rule}
	}
	return &validator.GenericValidator{}
}

func TestSSLink_StripBadWordsEnabled(t *testing.T) {
	badWords := []string{"blocked"}
	checkBadWords := func(fragment string) (string, bool, string) {
		if fragment == "" {
			return fragment, false, ""
		}
		decoded := utils.FullyDecode(fragment)
		for _, word := range badWords {
			if word == "" {
				continue
			}
			re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(word))
			if re.MatchString(decoded) {
				cleaned := re.ReplaceAllString(decoded, "")
				return cleaned, false, ""
			}
		}
		return fragment, false, ""
	}
	link := NewSSLink(badWords, utils.IsValidHost, checkBadWords, loadRuleForTest("ss"))
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:test123"))
	got, reason := link.Process("ss://" + userinfo + "@example.com:8388#blocked")
	if got == "" || strings.Contains(got, "blocked") {
		t.Fatalf("expected stripped name and accepted ss, got: %q reason: %q", got, reason)
	}
}

func TestSSLink(t *testing.T) {
	badWords := []string{"blocked"}
	checkBadWords := func(fragment string) (string, bool, string) {
		if fragment == "" {
			return fragment, false, ""
		}
		decoded := utils.FullyDecode(fragment)
		lower := strings.ToLower(decoded)
		for _, word := range badWords {
			if word != "" && strings.Contains(lower, word) {
				return "", true, "bad word"
			}
		}
		return fragment, false, ""
	}
	link := NewSSLink(badWords, utils.IsValidHost, checkBadWords, loadRuleForTest("ss"))

	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:test123"))
	tests := []struct {
		name   string
		input  string
		valid  bool
		reason string
	}{
		{"valid", "ss://" + userinfo + "@example.com:8388#my-server", true, ""},
		{"bad host", "ss://" + userinfo + "@localhost:8388", false, "invalid host"},
		{"bad word", "ss://" + userinfo + "@example.com:8388#blocked", false, "bad word"},
		{"invalid cipher", "ss://invalid@...", false, "invalid cipher"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := link.Process(tt.input)
			if tt.valid {
				if got == "" {
					t.Errorf("expected valid")
				}
			} else {
				if got != "" {
					t.Errorf("expected invalid")
				}
				if !strings.Contains(reason, tt.reason) {
					t.Errorf("reason = %q, want contains %q", reason, tt.reason)
				}
			}
		})
	}
}

func TestSSLink_SupportedCiphers(t *testing.T) {
	// НОВЫЙ ТЕСТ: проверяем, что поддерживаемые методы принимаются
	// AEAD методы и Shadowsocks 2022 должны работать
	badWords := []string{}
	checkBadWords := func(fragment string) (string, bool, string) {
		return fragment, false, ""
	}
	link := NewSSLink(badWords, utils.IsValidHost, checkBadWords, loadRuleForTest("ss"))

	tests := []struct {
		name   string
		method string
	}{
		{
			name:   "accept aes-128-gcm",
			method: "aes-128-gcm",
		},
		{
			name:   "accept aes-256-gcm",
			method: "aes-256-gcm",
		},
		{
			name:   "accept chacha20-poly1305",
			method: "chacha20-poly1305",
		},
		{
			name:   "accept xchacha20-poly1305",
			method: "xchacha20-poly1305",
		},
		{
			name:   "accept 2022-blake3-aes-128-gcm",
			method: "2022-blake3-aes-128-gcm",
		},
		{
			name:   "accept 2022-blake3-aes-256-gcm",
			method: "2022-blake3-aes-256-gcm",
		},
		{
			name:   "accept 2022-blake3-chacha20-poly1305",
			method: "2022-blake3-chacha20-poly1305",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userinfo := base64.RawURLEncoding.EncodeToString([]byte(tt.method + ":test123"))
			got, reason := link.Process("ss://" + userinfo + "@example.com:8388")
			if got == "" {
				t.Errorf("expected %s to be accepted, got error: %q", tt.method, reason)
			}
		})
	}
}

func TestSSLink_Matches(t *testing.T) {
	link := SSLink{}
	if !link.Matches("ss://...") {
		t.Error("Matches() = false, want true")
	}
}
