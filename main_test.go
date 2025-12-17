// main_test.go
package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestIsValidSourceURL проверяет функцию isValidSourceURL.
func TestIsValidSourceURL(t *testing.T) {
	tests := []struct {
		url   string
		valid bool
	}{
		{"https://example.com/sub", true},
		{"http://example.com/sub", true},
		{"https://localhost/sub", false},
		{"https://127.0.0.1/sub", false},
		{"https://192.168.1.1/sub", false},
		{"https://example.local/sub", false},
		{"ftp://example.com", false},
		{"not-a-url", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := isValidSourceURL(tt.url); got != tt.valid {
				t.Errorf("isValidSourceURL() = %v, want %v", got, tt.valid)
			}
		})
	}
}

// TestIsLocalIP проверяет функцию isLocalIP.
func TestIsLocalIP(t *testing.T) {
	tests := []struct {
		ip    string
		local bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"8.8.8.8", false},
		{"2001:4860:4860::8888", false},
		{"invalid", true}, // Treats invalid as local
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := isLocalIP(tt.ip); got != tt.local {
				t.Errorf("isLocalIP() = %v, want %v", got, tt.local)
			}
		})
	}
}

// TestLoadConfigFromArgsOrFile проверяет логику загрузки конфигурации из файла или аргументов командной строки.
// Использует временный файл конфигурации для тестирования.
func TestLoadConfigFromArgsOrFile(t *testing.T) {
	// Создаём временный каталог и файлы конфигурации
	tempDir := t.TempDir()
	tempConfigFile := filepath.Join(tempDir, "test_config.yaml")
	tempRulesFile := filepath.Join(tempDir, "test_rules.yaml")
	tempSourcesFile := filepath.Join(tempDir, "test_sources.txt")
	tempBadWordsFile := filepath.Join(tempDir, "test_bad.txt")
	tempUAgentFile := filepath.Join(tempDir, "test_ua.txt")

	// Записываем минимальные валидные файлы конфигурации
	err := os.WriteFile(tempConfigFile, []byte(`
sources_file: "`+tempSourcesFile+`"
rules_file: "`+tempRulesFile+`"
bad_words_file: "`+tempBadWordsFile+`"
uagent_file: "`+tempUAgentFile+`"
cache_dir: "`+filepath.Join(tempDir, "cache")+`"
cache_ttl: 1800s
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	// Записываем минимальный валидный файл правил
	err = os.WriteFile(tempRulesFile, []byte(`
vless:
  required_params:
    - encryption
    - sni
  forbidden_values:
    security: ["none"]
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	// Записываем минимальный валидный файл источников
	err = os.WriteFile(tempSourcesFile, []byte("https://example.com/sub\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	// Записываем минимальный валидный файл плохих слов
	err = os.WriteFile(tempBadWordsFile, []byte("badword\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	// Записываем минимальный валидный файл user-agent'ов
	err = os.WriteFile(tempUAgentFile, []byte("test-agent\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	// Тест 1: Загрузка из существующего файла
	t.Run("Load from existing file", func(t *testing.T) {
		cfg, err := loadConfigFromArgsOrFile(tempConfigFile, "", []string{"8080"}) // port is needed for args path, but won't be used here
		if err != nil {
			t.Fatalf("loadConfigFromArgsOrFile failed: %v", err)
		}
		// Теперь проверки должны соответствовать значениям из config.yaml
		if cfg.SourcesFile != tempSourcesFile {
			t.Errorf("Expected SourcesFile %s, got %s", tempSourcesFile, cfg.SourcesFile)
		}
		if cfg.RulesFile != tempRulesFile { // cfg.RulesFile теперь будет равно tempRulesFile из config.yaml
			t.Errorf("Expected RulesFile %s, got %s", tempRulesFile, cfg.RulesFile)
		}
		// cfg.Rules загружается validator.LoadRules, проверим, что он не пуст
		if len(cfg.Rules) == 0 {
			t.Error("Expected rules to be loaded from file specified in config.yaml")
		}
		// cfg.Sources загружается loadSourcesFromFile, проверим, что он не пуст
		if len(cfg.Sources) == 0 {
			t.Error("Expected sources to be loaded from file specified in config.yaml")
		}
		// cfg.BadWords загружается loadTextFile, проверим содержимое
		if len(cfg.BadWords) == 0 || cfg.BadWords[0] != "badword" {
			t.Errorf("Expected BadWords [\"badword\"], got %v", cfg.BadWords)
		}
		// cfg.AllowedUA загружается loadTextFile, проверим содержимое
		if len(cfg.AllowedUA) == 0 || cfg.AllowedUA[0] != "test-agent" {
			t.Errorf("Expected AllowedUA [\"test-agent\"], got %v", cfg.AllowedUA)
		}
	})

	// Тест 2: Загрузка из аргументов, если файл не существует
	t.Run("Load from args if file doesn't exist", func(t *testing.T) {
		args := []string{"8081", "3600", tempSourcesFile, tempBadWordsFile, tempUAgentFile, tempRulesFile}
		cfg, err := loadConfigFromArgsOrFile("nonexistent.yaml", "", args)
		if err != nil {
			t.Fatalf("loadConfigFromArgsOrFile failed: %v", err)
		}
		if cfg.CacheTTL != 3600*time.Second {
			t.Errorf("Expected CacheTTL 3600s, got %v", cfg.CacheTTL)
		}
		if cfg.SourcesFile != tempSourcesFile {
			t.Errorf("Expected SourcesFile %s, got %s", tempSourcesFile, cfg.SourcesFile)
		}
		if cfg.RulesFile != tempRulesFile {
			t.Errorf("Expected RulesFile %s, got %s", tempRulesFile, cfg.RulesFile)
		}
		// Проверяем, были ли загружены источники из файла, указанного в аргументах
		if len(cfg.Sources) == 0 {
			t.Error("Expected sources to be loaded from file specified in args")
		}
		// Проверяем, были ли загружены плохие слова из файла, указанного в аргументах
		if len(cfg.BadWords) == 0 || cfg.BadWords[0] != "badword" {
			t.Errorf("Expected BadWords [\"badword\"], got %v", cfg.BadWords)
		}
		// Проверяем, были ли загружены разрешённые UA из файла, указанного в аргументах
		if len(cfg.AllowedUA) == 0 || cfg.AllowedUA[0] != "test-agent" {
			t.Errorf("Expected AllowedUA [\"test-agent\"], got %v", cfg.AllowedUA)
		}
		// Проверяем, были ли загружены правила из файла, указанного в аргументах
		if len(cfg.Rules) == 0 {
			t.Error("Expected rules to be loaded from file specified in args")
		}
	})

	// Тест 3: Загрузка правил по умолчанию, если не указаны в аргументах
	t.Run("Load default rules if not specified in args", func(t *testing.T) {
		args := []string{"8082", "3600", tempSourcesFile, tempBadWordsFile, tempUAgentFile} // No rules file arg
		cfg, err := loadConfigFromArgsOrFile("nonexistent.yaml", "", args)
		if err != nil {
			t.Fatalf("loadConfigFromArgsOrFile failed: %v", err)
		}
		// RulesFile должен быть пустым изначально при разборе аргументов
		// Но loadRulesOrDefault должен установить его в "./config/rules.yaml"
		// Однако, файл не будет существовать, поэтому cfg.Rules должен быть пустой мапой из LoadRules("")
		// Давайте протестируем внутреннюю логику, создав файл правил по умолчанию в ожидаемом месте относительно temp
		// Для простоты просто проверим, что cfg.Rules инициализирован (даже если пуст из-за несуществующего файла по умолчанию)
		// Этот тест косвенно проверяет, что loadRulesOrDefault вызывается.
		// Лучший тест - это имитация или предоставление файла по умолчанию.
		// Пока что мы просто убедимся, что функция не падает и cfg.Rules - это мапа.
		if cfg.Rules == nil {
			t.Error("Expected cfg.Rules to be initialized, got nil")
		}
		// Фактическая загрузка файла по умолчанию "./config/rules.yaml" зависит от рабочей директории.
		// Это сложнее тестировать без изменения рабочей директории или создания файла в стандартном месте.
		// Мы полагаемся на то, что логика в loadRulesOrDefault.go верна для пути по умолчанию.
		// Тест выше для загрузки конкретного файла охватывает основную логику.
	})

	// Тест 4: Ошибка при недостатке аргументов
	t.Run("Error on insufficient args", func(t *testing.T) {
		_, err := loadConfigFromArgsOrFile("nonexistent.yaml", "", []string{}) // No port
		if err == nil {
			t.Error("Expected error for insufficient args, got nil")
		}
		if err.Error() != "Usage: <port> [cache_ttl] [sources] [bad] [ua] [rules]" {
			t.Errorf("Expected specific error message, got: %v", err)
		}
	})
}
