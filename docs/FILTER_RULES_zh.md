[EN](FILTER_RULES_en.md) / [RU](FILTER_RULES_ru.md)  / [ZH](FILTER_RULES_zh.md) 

此翻译由神经网络完成，如有任何错误，敬请谅解。

# `rules.yaml` 文档

`rules.yaml` 文件就像给 `sub-filter` 程序的 **规则列表**。这些规则帮助程序判断哪些代理链接是 **好的**（需要保留），哪些是 **坏的**（需要删除）。

可以想象 `sub-filter` 就像一个 **水过滤器**，但它过滤的不是水，而是 **代理订阅列表**。`rules.yaml` 就是这个 **过滤器的说明书**，告诉它 “干净的水”（好的代理链接）应该具备什么样的特征。

### 文件结构

`rules.yaml` 文件被分成几个 **部分**。每一部分负责 **一种类型的代理**。主要类型有：

*   `vless`
*   `vmess`
*   `trojan`
*   `hysteria2`
*   `ss` (Shadowsocks)

在每个部分里，可能有 **四种规则**：

1.  **`required_params`** (必需参数)
    *   这是一个 **参数列表**，这种类型的链接 **必须** 包含这些参数。
    *   如果缺少任何一个必需参数，该链接就被认为是 **坏的**，会被删除。
    *   例如：对于 `vless` 链接，通常 `encryption` 和 `sni` 是必需的。
2.  **`allowed_values`** (允许的值)
    *   这是 **特定参数** 的 **允许值** 列表。
    *   如果某个参数的值 **不在允许列表中**，该链接就被认为是 **坏的**，会被删除。
    *   例如：对于 `vless` 中的 `security` 参数，只允许 `tls` 和 `reality`。任何其他值，比如 `none`，都是不允许的。
3.  **`forbidden_values`** (禁止的值)
    *   这是 **特定参数** 的 **禁止值** 列表。
    *   如果某个参数的值 **在禁止列表中**，该链接就被认为是 **坏的**，会被删除。
    *   例如：以前 `security: ["none"]` 意味着 `security` 不能是 `none`。现在这个规则可能是 `conditional` 的一部分。
4.  **`conditional`** (条件规则)
    *   这些是 **复杂规则**，只有在满足某些 **特定条件** 时才会生效。
    *   它们有一个 `when` 部分（“当……时候”）。如果 `when` 里的 **所有条件** 都满足了，那么规则的其余部分才会被应用。
    *   例如：
        *   `when: { security: "reality" } require: ["pbk"]` — **当** `security` 是 `reality` 时，**要求** 链接里必须有 `pbk` 参数。
        *   `when: { type: "grpc" } require: ["serviceName"]` — **当** `type` (连接类型) 是 `grpc` 时，**要求** 链接里必须有 `serviceName` 参数。
        *   `when: { type: { not: "ws" } } forbidden_values: { security: ["none"] }` — **当** `type` **不等于** `ws` 时，**禁止** `security` 是 `none`。(这个新规则只允许 `type=ws` 时使用 `security=none`)。

### 文件中的示例

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

**解释:**

1.  **对于所有 `vless` 链接:**
    *   必须包含 `encryption` 和 `sni` 参数。
    *   `security` 参数只能是 `tls` 或 `reality`。
    *   `flow` 参数只能是 `xtls-rprx-vision` 或 `xtls-rprx-vision-udp443`。
2.  **另外:**
    *   如果 `security` 是 `reality`，那么 **必须** 有 `pbk` 参数。
    *   如果 `type` 是 `grpc`，那么 **必须** 有 `serviceName` 参数。
    *   **如果 `type` 不是 `ws`**，那么 `security` **不能** 是 `none`。