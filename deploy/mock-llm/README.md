# 本地 mock LLM（随机 401 / 429 / 5xx）

用于端到端验证重试逻辑。mock 实现 OpenAI Chat Completions 协议，每次请求按
`--error-rate` 随机返回一个错误码或正常补全；trilane-gui 通过内置的
`chat-completions` 适配器把 Responses 请求转成 Chat Completions 发过来，
上游状态码会原样透传。

## 1. 启动 mock

```bash
python deploy/mock-llm/mock_chat_llm.py --port 8787 --error-rate 0.7
```

参数：

- `--error-rate 0.7`：70% 概率返回错误，0 表示从不失败。
- `--include-overloaded`：额外返回 `503 server_is_overloaded`（按设计**不重试**，
  用来验证这个分支）。
- `--seed 42`：固定随机序列，便于复现。
- `--text`：成功时返回的 assistant 文本，默认 `MOCK_OK`。

每次请求会打印一行，例如：

```
[mock] #7 POST /v1/chat/completions -> 503 service_unavailable
[mock] #8 POST /v1/chat/completions -> 200 ok stream=True
```

## 2. 准备隔离的 TriLane home

不要动你真实的 `~/.trilane`。把配置放到一个独立目录，用 `TRILANE_HOME` 指过去：

```bash
mkdir -p /d/vstemp/trilane-mock-home
cp deploy/mock-llm/config.toml deploy/mock-llm/secrets.toml /d/vstemp/trilane-mock-home/
```

## 3. 构建并运行

```bash
D:/tools/build-trilane.bat release
```

```bash
TRILANE_HOME='D:\vstemp\trilane-mock-home' \
  D:/CodeWork/trilane/trilane-rs/target/release/trilane-gui.exe \
  --headless \
  --objective-file D:/CodeWork/trilane/deploy/mock-llm/task.md \
  --out-dir D:/vstemp/trilane-mock-out \
  --cwd D:/vstemp/trilane-mock-out \
  --audit-mode lab \
  --headless-timeout-sec 300
```

debug 构建把路径换成 `target/debug/trilane-gui.exe` 即可。

## 4. 看什么

- mock 终端：连续多行错误码后出现一次 `200 ok`，说明重试生效。
- trilane 日志：每次重试会输出 `Reconnecting... n/max`，其中
  `max` 来自 provider 的 `stream_max_retries`（配置里是 10）。
- 若 mock 用 `--include-overloaded`，遇到 `server_is_overloaded` 时**不会**重试，
  而是直接结束当前轮次，这是设计上的有意区分。

## 已知限制

- `Retry-After` 响应头在 `chat-completions` 适配器里没有透传（适配器只回传状态码
  和 body），所以走这条链路时重试间隔按指数退避计算，而不是服务端指定的值。
  该解析逻辑本身有单元测试覆盖。
- mock 成功响应只有 `MOCK_OK`，不满足 TriLane 的 runbook 阶段契约，因此工作流
  最终会报阶段未满足；这是预期的，本测试只关心 LLM 层的重试行为。
