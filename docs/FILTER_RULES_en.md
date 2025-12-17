[EN](FILTER_RULES_en.md) / [RU](FILTER_RULES_ru.md)  / [ZH](FILTER_RULES_zh.md) 

This translation was made using AI.

# Documentation for `rules.yaml`

The `rules.yaml` file is like a **list of rules** for the `sub-filter` program. These rules help the program decide which proxy links are **good** (and should be kept) and which are **bad** (and should be removed).

Think of `sub-filter` as a **water filter**, but instead of filtering water, it filters **proxy subscription lists**. `rules.yaml` is the **instruction manual for the filter**, telling it what characteristics "clean water" (good proxy links) should have.

### File Structure

The `rules.yaml` file is divided into **sections**. Each section is responsible for **one type of proxy**. Here are the main types:

*   `vless`
*   `vmess`
*   `trojan`
*   `hysteria2`
*   `ss` (Shadowsocks)

Within each section, there can be **four kinds of rules**:

1.  **`required_params`** (Required Parameters)
    *   This is a list of **parameters** that **must** be present in a link of this type.
    *   If any required parameter is **missing**, the link is considered **bad** and is removed.
    *   Example: For `vless`, `encryption` and `sni` are often required.
2.  **`allowed_values`** (Allowed Values)
    *   This is a list of **allowed** values for **specific parameters**.
    *   If a parameter's value is **not in the allowed list**, the link is considered **bad** and is removed.
    *   Example: For the `security` parameter in `vless`, only `tls` and `reality` are allowed. Any other value, like `none`, is forbidden.
3.  **`forbidden_values`** (Forbidden Values)
    *   This is a list of **forbidden** values for **specific parameters**.
    *   If a parameter's value is **in the forbidden list**, the link is considered **bad** and is removed.
    *   Example: Previously, `security: ["none"]` meant `security` could not be `none`. Now this rule might be part of `conditional`.
4.  **`conditional`** (Conditional Rules)
    *   These are **complex rules** that apply **only under certain conditions**.
    *   They have a `when` part ("when"). If **all conditions** in `when` are met, then the rest of the rule is applied.
    *   Examples:
        *   `when: { security: "reality" } require: ["pbk"]` — **When** `security` is `reality`, **require** the `pbk` parameter to be present.
        *   `when: { type: "grpc" } require: ["serviceName"]` — **When** `type` (connection type) is `grpc`, **require** the `serviceName` parameter to be present.
        *   `when: { type: { not: "ws" } } forbidden_values: { security: ["none"] }` — **When** `type` is **NOT** `ws`, **forbid** `security` from being `none`. (This new rule allows `security=none` only for `type=ws`).

### Example from the file

```yaml
vless:
  required_params:
    - encryption
    - sni
  allowed_values:
    security: ["tls", "reality"]
    flow:
      - "xtls-rprx-vision"
      - "xtls-rprx-vision-udp443"
  conditional:
    - when: { security: "reality" }
      require: ["pbk"]
    - when: { type: "grpc" }
      require: ["serviceName"]
    - when: { type: { not: "ws" } }
      forbidden_values: { security: ["none"] }
```

**Explanation:**

1.  **For all `vless` links:**
    *   The parameters `encryption` and `sni` must be present.
    *   The `security` parameter can only be `tls` or `reality`.
    *   The `flow` parameter can only be `xtls-rprx-vision` or `xtls-rprx-vision-udp443`.
2.  **Additionally:**
    *   If `security` is `reality`, then the `pbk` parameter **must** be present.
    *   If `type` is `grpc`, then the `serviceName` parameter **must** be present.
    *   **If `type` is NOT `ws`**, then `security` **cannot** be `none`.

---
