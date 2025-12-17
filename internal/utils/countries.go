// internal/utils/countries.go
package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// CountryInfo представляет информацию о стране из countries.yaml.
type CountryInfo struct {
	CCA3       string                 `mapstructure:"cca3"`
	Flag       string                 `mapstructure:"flag"`
	Name       CountryNames           `mapstructure:"name"`
	NativeName map[string]CountryName `mapstructure:"nativeName"`
}

// CountryNames содержит официальное и обычное название страны.
type CountryNames struct {
	Common   string `mapstructure:"common"`
	Official string `mapstructure:"official"`
}

type CountryName struct {
	Common   string `mapstructure:"common"`
	Official string `mapstructure:"official"`
}

type Name struct {
	Common   string `json:"common"`
	Official string `json:"official"`
}

type Country struct {
	Name       Name            `json:"name"`
	NativeName map[string]Name `json:"nativeName"`
	Cca2       string          `json:"cca2"`
	Cca3       string          `json:"cca3"`
	Flag       string          `json:"flag"`
}

type CountryYAML struct {
	CCA3       string          `yaml:"cca3"`
	Flag       string          `yaml:"flag"`
	Name       string          `yaml:"name"` // только common
	NativeName map[string]Name `yaml:"nativeName,omitempty"`
}

// LoadCountries загружает информацию о странах из YAML-файла.
func LoadCountries(filePath string) (map[string]CountryInfo, error) {
	if filePath == "" {
		return make(map[string]CountryInfo), nil // Пустая мапа, если файл не указан
	}

	viper.SetConfigFile(filePath)
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".yaml" || ext == ".yml" {
		viper.SetConfigType("yaml")
	}

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read countries file: %w", err)
	}

	var countries map[string]CountryInfo
	if err := viper.Unmarshal(&countries); err != nil {
		return nil, fmt.Errorf("failed to unmarshal countries: %w", err)
	}

	return countries, nil
}

// GetCountryFilterStrings возвращает список строк (CCA3, Flag, Name), которые нужно искать
// в фрагменте имени прокси-ссылки для заданного кода страны.
// Возвращает пустой слайс, если код страны не найден.
func GetCountryFilterStrings(countryCode string, countryMap map[string]CountryInfo) []string {
	if countryCode == "" {
		return []string{}
	}
	countryCode = strings.ToUpper(countryCode)
	info, ok := countryMap[countryCode]
	if !ok {
		return []string{} // Код страны не найден, фильтровать нечем
	}

	var searchTerms []string
	// Добавляем CCA3
	searchTerms = append(searchTerms, info.CCA3)
	// Добавляем Flag
	searchTerms = append(searchTerms, info.Flag)
	// Добавляем Common и Official из Name
	searchTerms = append(searchTerms, info.Name.Common)
	searchTerms = append(searchTerms, info.Name.Official)
	// Добавляем Common и Official из NativeName
	for _, nativeEntry := range info.NativeName {
		searchTerms = append(searchTerms, nativeEntry.Common)
		searchTerms = append(searchTerms, nativeEntry.Official)
	}

	// Удаляем дубликаты и пустые строки
	seen := make(map[string]bool)
	var uniqueSearchTerms []string
	for _, term := range searchTerms {
		if term != "" && !seen[term] {
			seen[term] = true
			uniqueSearchTerms = append(uniqueSearchTerms, term)
		}
	}

	return uniqueSearchTerms
}

// IsFragmentMatchingCountry проверяет, содержит ли фрагмент (якорь #...) какие-либо из строк фильтрации страны.
// Сравнение регистронезависимое.
func IsFragmentMatchingCountry(fragment string, filterStrings []string) bool {
	if len(filterStrings) == 0 {
		return true // Если нет строк для фильтрации, всё подходит (режим "всё" или пустой код)
	}
	lowerFragment := strings.ToLower(FullyDecode(fragment))
	for _, searchTerm := range filterStrings {
		if strings.Contains(lowerFragment, strings.ToLower(searchTerm)) {
			return true
		}
	}
	return false
}

func GenerateCountries() {
	resp, err := http.Get("https://restcountries.com/v3.1/all?fields=cca2,cca3,flag,name,nativeName")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	var countries []Country
	if err := json.Unmarshal(body, &countries); err != nil {
		panic(err)
	}
	countryMap := make(map[string]CountryYAML)
	for _, c := range countries {
		cca2 := strings.ToUpper(c.Cca2)
		if cca2 == "" {
			continue
		}
		countryMap[cca2] = CountryYAML{
			CCA3:       strings.ToUpper(c.Cca3),
			Flag:       c.Flag,
			Name:       c.Name.Common,
			NativeName: c.NativeName,
		}
	}
	keys := make([]string, 0, len(countryMap))
	for k := range countryMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sortedMap := make(map[string]CountryYAML)
	for _, k := range keys {
		sortedMap[k] = countryMap[k]
	}
	yamlData, err := yaml.Marshal(sortedMap)
	if err != nil {
		panic(err)
	}

	// 👇 ДОБАВЛЕНО: создание директории
	configDir := "./config"
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		panic(fmt.Errorf("failed to create config dir: %w", err))
	}

	if err := os.WriteFile(filepath.Join(configDir, "countries.yaml"), yamlData, 0o644); err != nil {
		panic(err)
	}
	fmt.Println("countries.yaml created")
}
