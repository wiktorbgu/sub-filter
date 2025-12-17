// internal/validator/generic.go
package validator

import (
	"fmt"
	"strings"
)

// <-- Убедиться, что импортирован
type GenericValidator struct {
	Rule Rule
}

func (gv *GenericValidator) Validate(params map[string]string) ValidationResult {
	// 1. Обязательные параметры (без изменений)
	for _, param := range gv.Rule.RequiredParams {
		if _, exists := params[param]; !exists {
			return ValidationResult{
				Valid:  false,
				Reason: fmt.Sprintf("missing required parameter: %s", param),
			}
		}
	}

	// 2. Запрещённые значения — регистронезависимые
	for param, forbidden := range gv.Rule.ForbiddenValues {
		if value, exists := params[param]; exists {
			lowerValue := strings.ToLower(value)
			for _, f := range forbidden {
				if lowerValue == strings.ToLower(f) {
					return ValidationResult{
						Valid:  false,
						Reason: fmt.Sprintf("forbidden value for %s: %q", param, value),
					}
				}
			}
		}
	}

	// 3. Разрешённые значения — регистронезависимые
	for param, allowed := range gv.Rule.AllowedValues {
		if value, exists := params[param]; exists {
			lowerValue := strings.ToLower(value)
			found := false
			for _, a := range allowed {
				if lowerValue == strings.ToLower(a) {
					found = true
					break
				}
			}
			if !found {
				return ValidationResult{
					Valid:  false,
					Reason: fmt.Sprintf("invalid value for %s: %q (allowed: %v)", param, value, allowed),
				}
			}
		}
	}

	// 4. Условные правила — ОСТАВЛЯЕМ чувствительными к регистру (т.к. это логические условия, а не пользовательский ввод)
	for _, cond := range gv.Rule.Conditional {
		match := true
		for k, v := range cond.When {
			if value, exists := params[k]; !exists || value != v {
				match = false
				break
			}
		}
		if match {
			for _, req := range cond.Require {
				if _, exists := params[req]; !exists {
					return ValidationResult{
						Valid:  false,
						Reason: fmt.Sprintf("missing required parameter %s when %v", req, cond.When),
					}
				}
			}
		}
	}

	return ValidationResult{Valid: true}
}
