# LLM 错误统一重试设计

## 1. 背景与目标

内网服务器不稳定，LLM 请求会出现各种错误（401、503、连接重置、SSE 中断、网关超时等）。
当前代码的重试分散在四层，分类标准不一致，部分错误（裸 503、401）在 GUI 层会被直接判死。

本次改动的目标：

1. **任意 LLM 错误都进入重试**（用户取消等控制流除外）。
2. **重试次数可配置**（核心请求层、GUI lane 层各自可配）。
3. **重试间隔渐进**（指数退避 + 抖动 + 上限），避免固定步长和指数爆炸。

---

## 2. 现状

### 2.1 四层重试

| 层 | 位置 | 触发条件 | 次数 | 间隔 |
|---|---|---|---|---|
| HTTP 传输层 | `trilane-rs/codex-client/src/retry.rs:22` | 429（默认关）、5xx、超时、网络 | `request_max_retries`，默认 4 | 200ms × 2^(n-1) + 抖动 |
| 401 鉴权恢复 | `trilane-rs/core/src/client.rs:1287` / `:1976` | 仅 401 | 刷新 token 后重发 1 次 | 无 |
| 流 / turn 层 | `trilane-rs/core/src/session/turn.rs:956`、`core/src/responses_retry.rs:22` | `CodexErr::is_retryable()` | `stream_max_retries`，默认 5 | `core/src/util.rs:85`，200ms × 2^(n-1) |
| GUI lane 层 | `trilane-rs/trilane-gui/src/main_status.inc.rs:27` | **错误文本包含 429 / rate limit / timeout 等 5 个关键词** | `WORKFLOW_LANE_MAX_ATTEMPTS = 3` | 固定 20 / 45 / 90 秒（实际只用到 20、45） |
| 容器层（deploy） | `deploy/cybergym_batch.py:1190` | 容器非零退出 | `--agent-retries`，默认 1 | 60s × attempt |

### 2.2 问题

- `is_retryable()`（`trilane-rs/protocol/src/error.rs:178`）把 `ServerOverloaded`、`RetryLimit`、`InvalidRequest` 等一律判为不可重试，裸 503 走到 `UnexpectedStatus` 才可重试，而带 `error.code=server_is_overloaded` 的 503 直接失败。
- GUI lane 层按字符串匹配，**裸 503（`unexpected status 503 ...`）和 401 都不在列表里**，所以 workflow 里表现为 lane failed 而不是重试。
- 401 在没有 auth manager（纯 API key provider）时退化为 `UnexpectedStatus`，会被流层重试 5 次；有 auth manager 时又只刷新一次。行为不一致。
- 退避没有上限：`stream_max_retries` 调到 100 时，第 100 次间隔是 200ms × 2^99，实际会溢出/等于永久挂起。
- lane 重试次数和间隔是硬编码常量，容器里无法调整。
- lane 层两个调用点语义不同却共用一套判定：`main_agent_loop.inc.rs:223` 喂的是模型错误文本，`main_workflow_runtime.inc.rs:456` 喂的是 app-server RPC 失败（`thread start failed` / `turn start failed`）。
- lane 的 `attempts` 在每次启动前自增（`main_types.inc.rs:289`），第一次失败时已是 1，导致 `workflow_lane_retry_delay` 的 `0` 分支不可达、`_ => 90` 在 max=3 时也不可达。

---

## 3. 方案

### 3.1 核心：`is_retryable()` 改为「默认重试，显式排除」

文件：`trilane-rs/protocol/src/error.rs:178`

改为：**除下表列出的变体外，全部返回 `true`。**

| 保持 `false` | 原因 |
|---|---|
| `TurnAborted`、`Interrupted` | 用户取消，不是错误 |
| `Fatal`、`EnvVar`、`Sandbox(_)`、`Landlock*`、`UnsupportedOperation`、`ThreadNotFound`、`SessionConfiguredNotFirstEvent`、`AgentLimitReached`、`Spawn`、`InternalAgentDied` | 配置 / 环境 / 编程错误，重试无意义 |
| `ContextWindowExceeded` | 请求本身超长，原样重试必然再超；需要先压缩历史（`turn.rs:989`） |
| `InvalidImageRequest`、`InvalidToolArgumentsRequest` | 需要先修历史再重试（`turn.rs:363`、`:382`），若在流层盲重试会绕过修复逻辑 |

改为 `true` 的变体：`ServerOverloaded`、`RetryLimit`、`InvalidRequest`、`QuotaExceeded`、`UsageNotIncluded`、`UsageLimitReached`、`CyberPolicy`、`RefreshTokenFailed`，以及原有的 `UnexpectedStatus`（含 401/403/404/429/5xx）、`Stream`、`Timeout`、`RequestTimeout`、`ConnectionFailed`、`ResponseStreamFailed`、`InternalServerError`、`Io`、`Json`。

> 额度类（`UsageLimitReached` / `UsageNotIncluded` / `QuotaExceeded`）也重试，但需要额外改一处：`run_sampling_request` 在 `turn.rs:993` 对 `UsageLimitReached` 做了提前 return，会绕过重试判定。改为先 `update_rate_limits` 上报额度快照，再让它进入正常重试流程；重试预算耗尽后仍由 `run_turn` 的兜底分支发出错误事件并触发 `GoalRuntimeEvent::UsageLimitReached`。
>
> 说明：`RetryLimit` 表示 HTTP 层已耗尽预算，放开后由流层再给一轮机会；两层预算独立且嵌套，最大尝试次数 = `(request_max_retries+1) × (stream_max_retries+1)`。按新默认值 9 × 11 = 99 次请求，最坏等待约 111s + 11 × 51s ≈ 11 分钟。

### 3.2 重试次数可配置

| 层 | 配置方式 | 默认 | 取值范围 |
|---|---|---|---|
| HTTP 请求层 | `config.toml` → `[model_providers.<id>] request_max_retries`（已存在，`model-provider-info/src/lib.rs:291`） | 4 → **8** | 0–100 |
| 流 / turn 层 | 同上 `stream_max_retries`（已存在，`model-provider-info/src/lib.rs:298`） | 5 → **10** | 0–100 |
| GUI lane 层 | 新增环境变量 `TRILANE_LANE_MAX_ATTEMPTS`（沿用 `workflow_lane_idle_timeout()` 的读取模式，`main_status.inc.rs:18`） | 3 → **8** | 1–20 |
| headless / 容器 | 同上环境变量（`docker run -e TRILANE_LANE_MAX_ATTEMPTS=8`） | 同 lane | 1–20 |

容器场景：`deploy/cybergym_batch.py` 里通过 `-e TRILANE_LANE_MAX_ATTEMPTS=8` 注入即可，无需改镜像内 config.toml。

### 3.3 渐进退避 + 上限

统一成「指数退避 + 抖动 + 封顶」：

```
delay = min(base × 2^(attempt-1) × random(0.9, 1.1), max_delay)
```

抖动在封顶之前施加，所以单次间隔严格不超过 `max_delay`。

| 位置 | base | max_delay |
|---|---|---|
| `core/src/util.rs:85`（流层） | 200ms | **新增 30s 上限** |
| `codex-client/src/retry.rs:38`（HTTP 层） | 200ms | **新增 30s 上限** |
| GUI lane（`main_status.inc.rs:9`） | 新增 `TRILANE_LANE_RETRY_BASE_SECS`，默认 20s | 新增 `TRILANE_LANE_RETRY_MAX_SECS`，默认 30s |

服务端返回的 `retry-after` / Azure `retry-after-ms` 仍然优先（`codex-api/src/sse/responses.rs:487`），但同样受 `max_delay` 封顶。

### 3.4 单次间隔上限

**现状：代码里没有任何时间上限。** 退避公式无封顶，`stream_max_retries` 配到 100 时第 100 次的间隔是 200ms × 2^99，实际等于永久挂起。

本次只加**单次间隔上限 30s**，不引入总时间预算：

1. `core/src/util.rs` 的 `backoff()`：`min(200ms × 2^(n-1) × 抖动, 30s)`
2. `codex-client/src/retry.rs` 的 `backoff()`：同上
3. GUI lane：`min(20s × 2^(attempts-1) × 抖动, 30s)`

封顶后的实际序列和累计等待：

| 层 | 重试次数 | 单次间隔 | 累计等待 |
|---|---|---|---|
| HTTP 请求层（当前默认 4） | 4 | 0.2 / 0.4 / 0.8 / 1.6s | ≈ 3s |
| HTTP 请求层（新默认 8） | 8 | 0.2 → 25.6s | ≈ 51s |
| 流层（当前默认 5） | 5 | 0.2 → 3.2s | ≈ 6.2s |
| 流层（新默认 10） | 10 | 0.2 → 30s（第 9 次起封顶） | ≈ 111s |
| 流层（配到 20） | 20 | 第 9 次起固定 30s | ≈ 411s |
| 流层（配到 100） | 100 | 第 9 次起固定 30s | ≈ 47min |
| GUI lane（新默认 8 次启动，7 次重试） | 7 | 20 + 30×6 | 200s |

上限只保证**单次**不会失控；总耗时仍随次数线性增长（每次最多 30s），由配置者按需决定次数。

已有的兜底（不在重试层，但能限制整体）：`--headless-timeout-sec`（默认 7200s）、lane idle timeout（默认 600s，只对 `Running` 生效，重试等待中的 lane 是 `Queued`，不会被它中断）。

### 3.5 429 的处理

429 在 `codex-api/src/api_bridge.rs:83-112` 分三条支路：

| 429 内容 | 映射 | 是否重试 |
|---|---|---|
| `error.type = usage_limit_reached` | `UsageLimitReached` | **是**。先上报额度快照，再进入流层重试 |
| `error.type = usage_not_included` | `UsageNotIncluded` | **是** |
| 其它（普通限流） | `RetryLimit` | **是** |

HTTP 传输层的 `retry_429` 保持 `false`（`model-provider-info/src/lib.rs:254`）：429 统一交给流层处理，避免两层预算相乘。

**额度类 429 的退避**：`UsageLimitReachedError` 带 `resets_at`（可能在一小时后）。不能按 `resets_at` 睡，否则单轮直接卡死；仍然用 3.3 的指数退避（封顶 30s），预算耗尽后由 `run_turn` 发出错误事件并触发 `GoalRuntimeEvent::UsageLimitReached`，UI 仍能看到额度和重置时间。

**需要补的缺口**：429 一般带 `Retry-After` 响应头，但当前代码只解析 SSE 事件里的 `retry_after`（Azure，`codex-api/src/sse/responses.rs:487`），HTTP 响应头没有解析。直接放开重试会用 200ms/400ms 退避，很可能马上又撞上限流。

改法：在 `api_bridge.rs` 的 429 分支从 `headers` 提取 `retry-after`（秒或 HTTP-date）以及 `x-ratelimit-reset-requests` / `x-ratelimit-reset-tokens`，挂到 `RetryLimitReachedError` 新增的 `retry_after: Option<Duration>` 字段上，`responses_retry.rs` 优先使用它（同样受 30s 上限约束）。

### 3.6 401 统一行为

保持「先刷新凭证再重发」的现有逻辑（`core/src/client.rs:1976`），并补上退避：

- 刷新成功 → **按 HTTP 传输层同样的退避等待后再重发**（`200ms × 2^(n-1)`，抖动，封顶 30s），不再立即 `continue`。
- 刷新失败且可重试 → 进入正常重试预算（不再依赖 `UnexpectedStatus` 的隐式行为）。
- 永久性刷新失败 → `RefreshTokenFailed`，进入正常重试预算（按 3.1 已改为可重试）。

实现位置：`stream_responses_api`（`core/src/client.rs:1287-1305`）和 `stream_responses_websocket`（`core/src/client.rs:1407-1419`）两处 `continue` 之前加 sleep；用循环内的 auth 重试计数，复用 `codex-client` 的 `backoff()` 公式和 30s 上限，与 HTTP 传输层保持一致。

### 3.7 GUI lane 层改用结构化错误信息

文件：`trilane-rs/trilane-gui/src/main_status.inc.rs:27`

GUI 拿到的 `TurnError` 已经带结构化字段（`app-server-protocol/src/protocol/v2/thread_data.rs:187`）：

```rust
pub struct TurnError {
    pub message: String,
    pub codex_error_info: Option<CodexErrorInfo>,
    pub additional_details: Option<String>,
}
```

`CodexErrorInfo` 里有 `Unauthorized`、`ServerOverloaded`、`HttpConnectionFailed { http_status_code }`、`ResponseStreamDisconnected { .. }` 等（`protocol/src/protocol.rs:1601`），完全够用来分类，不需要再匹配文本。

改法：

- `is_retryable_lane_error` 改成 `should_retry_lane_error(&TurnError)`：
  - `codex_error_info` 为 `None` → 重试（默认放开）；
  - 明确表示用户中断的（`ActiveTurnNotSteerable` 等）→ 不重试；
  - 其余一律重试。
- 字符串匹配只作为 `codex_error_info == None` 时的兜底，且只做**排除**（`interrupted` / `aborted`），不做包含匹配。
- 两个调用点都要改：
  - `main_agent_loop.inc.rs:223` —— 来自 `TurnCompleted` 的模型错误，改为传整个 `TurnError`。
  - `main_workflow_runtime.inc.rs:456` —— **注意这里喂的是 app-server RPC 失败**（`thread start failed: ...` / `turn start failed: ...`），不是模型错误，没有 `TurnError`；这一路应改为无条件重试（受 `can_retry` 限制）。

### 3.8 lane 重试计数与延迟的现状修正

`attempts` 在每次启动前由 `mark_starting` 自增（`main_types.inc.rs:289`），所以第一次失败时 `attempts` 已经是 1。现有 `workflow_lane_retry_delay` 的 `0 | 1 => 20` 分支里 `0` 永远不会出现，`_ => 90` 在 max=3 时也永远走不到。

新公式按 `attempts` 计算：

```
delay = min(base × 2^(attempts-1), max_delay)
```

即默认 base=20s、max=30s 时：第 1 次失败等 20s，之后固定 30s。

`ActiveLane.last_error` 目前只写不读（`main_types.inc.rs:237`），可以在状态文本里用上，方便报告里看到最后一次失败原因。

### 3.9 观测

- 流层已有 `Reconnecting... n/max` 提示（`responses_retry.rs:67`）。
- lane 层状态文本改为显示 `attempt=n/max next_retry_in=Ns`，便于在 `result.json` / 报告里看到重试轨迹。

---

## 4. 改动文件清单

| 文件 | 改动 |
|---|---|
| `trilane-rs/protocol/src/error.rs` | `is_retryable()` 分类重写、`RetryLimitReachedError` 增加 `retry_after` + 单元测试 |
| `trilane-rs/codex-api/src/api_bridge.rs` | 429 分支解析 `Retry-After` 等响应头 |
| `trilane-rs/core/src/client.rs` | 401 重发前加退避等待（HTTP / WebSocket 两处） |
| `trilane-rs/core/src/session/turn.rs` | `UsageLimitReached` 提前 return 改为上报额度后进入重试 |
| `trilane-rs/core/src/util.rs` | `backoff()` 加上限 |
| `trilane-rs/codex-client/src/retry.rs` | `backoff()` 加上限 |
| `trilane-rs/core/src/responses_retry.rs` | 服务端 `retry-after` 也受 30s 封顶 |
| `trilane-rs/model-provider-info/src/lib.rs` | 默认值调整（可选） |
| `trilane-rs/trilane-gui/src/main.rs` | 常量改为函数读取环境变量 |
| `trilane-rs/trilane-gui/src/main_status.inc.rs` | lane 退避公式、可配置读取、结构化重试判定 |
| `trilane-rs/trilane-gui/src/main_agent_loop.inc.rs` | 传整个 `TurnError` 给判定函数 |
| `trilane-rs/trilane-gui/src/main_workflow_runtime.inc.rs` | RPC 启动失败路径改为无条件重试 |
| `trilane-rs/trilane-gui/src/main_types.inc.rs` | `can_retry()` 使用动态上限 |
| `trilane-rs/trilane-gui/src/main_tests.inc.rs` | 更新重试相关测试 |

---

## 5. 风险与取舍

- **永久性错误也会消耗重试**（错误 API key、参数错误、额度耗尽）。这是本次有意接受的代价：内网不稳定时，误判为永久的错误代价更高。用可配置的次数和单次间隔上限控制总耗时。
- **两层嵌套会放大请求量**：HTTP 层 8 次 × 流层 10 次，最坏一次 sampling 会发 99 次请求、累计等待约 11 分钟。嫌重的话优先调小 `request_max_retries`（外层预算已经足够）。
- **额度类错误会先重试再报错**：额度真正耗尽时，用户要等重试预算走完才会看到额度提示，中间只会看到 `Reconnecting...`。如果这个体验不可接受，可以在额度错误里加一个「只重试 N 次」的单独上限。
- **401 错误重试可能反复触发 token 刷新**。`UnauthorizedRecovery` 的步骤是有限的（`has_next()` 用尽后不再刷新），加上 30s 间隔上限，不会刷爆鉴权服务。
- **重试次数调大后单轮耗时变长**，需要配合 `--headless-timeout-sec` 和 lane idle timeout 一起调。
- **行为变化**：之前直接失败的 400/429/503 现在会先重试，日志里会出现更多 `Reconnecting...`。

---

## 6. 验证

1. 单元测试：
   - `is_retryable()` 全变体矩阵（每个变体断言 true/false）。
   - `backoff()` 封顶：第 20 次仍不超过 30s。
   - lane 退避：`attempts` 为 1/2/3 时对应 20/30/30 秒。
   - 环境变量解析：非法值回退默认。
2. 集成：
   - 本地起一个 mock provider：前 3 次返回 503，第 4 次返回 200，确认 turn 成功且日志有 3 次重试。
   - mock 返回 401 且 auth 可恢复，确认刷新后**间隔 200ms 起退避再重发**，而不是立即重发。
   - mock 返回 429 且带 `Retry-After: 5`，确认第二次请求在 5 秒后才发出；返回 `usage_limit_reached` 时确认会先重试、预算耗尽后才上报额度。
3. 回归：
   - `cargo test -p codex-protocol -p codex-api -p codex-core -p trilane-gui`
   - 跑一次 `deploy/tasks/smoke.txt` 的 headless 任务，确认 `result.json` 正常产出。
4. 端到端（已完成）：
   - `deploy/mock-llm/mock_chat_llm.py` 随机返回 401/429/500/502/503，配合
     `adapter = "chat-completions"` 的 provider 配置跑 headless 任务。
   - 实测 37 次请求中 29 次随机错误，流层重试 12 次，退避从 193ms 翻倍到 6.1s，
     轮次最终在重试后完成。

---

## 7. 已定项

- `deploy/cybergym_batch.py` 的容器级 `--agent-retries` **保持默认 1**。容器内已经有 HTTP 8 次、流层 10 次、lane 8 次三层重试，容器级只作为最后的兜底，不需要再加大。
