# CyberGym 批量跑批（部署目录）

这个目录是**自包含**的：部署到新机器只需要 `deploy/` 这一个目录，加上三个镜像和数据集。

```
宿主 docker daemon
 └─ trilane-batch-runner    ← 编排器：python + 跑批脚本，不跑智能体
      │  通过 docker.sock 拉起 ↓
      └─ trilane-dind-<task>     ← 每任务独立的 DinD daemon（--privileged）
           ├─ trilane-headless   ← 智能体本体，跑在 dind 内部
           └─ n132/arvo:<id>-vul ← 智能体在同一个 dind 里起的目标容器
```

智能体容器由 dind 自己创建（`docker exec <dind> docker run ...`），所以它只能看到这个
私有 daemon：宿主上的其他容器、镜像、卷对它完全不可见，`docker system prune` 之类的
命令也只作用于本任务的 dind。

服务器上**不需要 Python、不需要构建工具链**，只要 Docker。

---

## 目录内容

| 文件 | 用途 |
| --- | --- |
| `cybergym_batch.py` | 跑批脚本本体（取任务包 → 生成提示词 → 跑 TriLane → 提交 PoC） |
| `triage.py` / `triage.sh` | 失败排障：对 `runs/<批次>/` 输出状态分类、阶段进度、断点、错误统计、结论 |
| `batch-runner.Dockerfile` | 编排器镜像，把上面的脚本烤进去 |
| `compose.batch.yaml` | 推荐方式：compose 编排（`network_mode: host` + 同路径挂载） |
| `.env.example` | 配置模板，复制成 `.env` 后填 |
| `tasks/tasks.txt` | 任务列表，一行一个 id |
| `images/` | **已导出的镜像包**，拷到服务器直接 `docker load` |
| `README.md` | 本文件 |

`images/` 里是现成的（本机构建、已校验）：

| 包 | 大小 | 内容 |
| --- | --- | --- |
| `trilane-batch-runner.tgz` | 71MB | 编排器 1.0.24，内含 `cybergym_batch.py` + `triage.py` + `triage.sh` |
| `trilane-headless-1.0.8.tar.gz` | 298MB | 智能体本体 |
| `SHA256SUMS` | — | 校验和，服务器上 `sha256sum -c` 验一遍 |

`trilane-headless:1.0.8` 的 Rust 二进制在 WSL（Ubuntu 24.04）里编译后 COPY 进 runtime-only 镜像，
基础运行层也是 Ubuntu 24.04；镜像构建不再包含 cargo/前端编译，详见 `docker/WSL_BUILD_PLAN.md`。

暂**不含**目标镜像（`n132/arvo:<id>-vul`，每个 0.5–2GB）和数据集，按 §2 单独打包搬运。

---

## 1. 服务器要有什么

| 项 | 说明 |
| --- | --- |
| Docker | 20.10+，能 `docker run`。**daemon 必须与服务端同一台**（服务端要靠它起目标容器） |
| 磁盘 | 两个镜像 ~1GB；数据集 4GB；每任务解包 ~0.25GB；目标镜像每个 0.5–2GB |
| 内存 | 8GB 起。每个目标容器上限 4GB，**并发 N 就要 N×4GB** |
| DinD | 默认 `--isolation dind`：宿主需允许 `--privileged`；每个并发任务额外预留 (目标镜像 + 智能体镜像 + `RUN_SPACE_GB`，默认 5GB) 磁盘（dind 的 `/var/lib/docker` 是 Docker named volume，里面要放两个镜像和运行数据）。`host` 模式不导入镜像，只按 `RUN_SPACE_GB` 预留运行盘 |

---

## 2. 导入镜像与数据

### 新服务器（镜像包已在本目录）

`deploy/images/` 里已经有编排器和智能体两个镜像包，直接导入即可
（`.tgz` 与 `.tar.gz` 都是 gzip 压缩的 tar，新导出统一用 `.tar.gz`，这里两种都收）：

```bash
cd deploy
# 先校验（可选，但推荐）
(cd images && sha256sum -c SHA256SUMS)

for f in images/*.tgz images/*.tar.gz; do gunzip -c "$f" | docker load; done
```

> `images/` 顶层只有**当前要用的**包。要回滚到旧编排器时，从 git 历史里取对应的
> `batch-runner.Dockerfile` 重建，或找打包机重新导出——历史镜像包不留在这里。

| 包 | 大小 | 内容 |
| --- | --- | --- |
| `images/trilane-batch-runner.tgz` | 71MB | 编排器（1.0.24），内含 `cybergym_batch.py` + `triage.py` |
| `images/trilane-batch-runner-1.0.24.tgz` | 71MB | 同上，带版本号的副本 |
| `images/trilane-headless-1.0.8.tar.gz` | 298MB | 智能体本体 |
| `images/SHA256SUMS` | — | 上面几个包的校验和 |

目标镜像（`n132/arvo:<id>-vul`）要另外从打包机带过来，见下。

DinD 模式（默认 `--isolation dind`）还需要 `docker:dind` 镜像：

```bash
docker pull docker:dind
# 或从打包机带过来：
# docker save docker:dind | gzip > docker-dind.tgz
```

### 打包机（缺的包在这里生成）

```bash
docker save n132/arvo:1065-vul | gzip > arvo-1065.tgz      # 只需要 -vul
docker save n132/arvo:3938-vul  | gzip > arvo-3938.tgz     # 每个任务一个

tar czf cybergym_data.tgz -C /path/to cybergym_data
```

> 服务端自己还需要对应的 `-fix` 镜像来验 fix 侧，那是**服务端**的事（`/opt/cybergym`），
> 跑批这边只需要 `-vul`。

### 新服务器（接着导入）

```bash
for f in *.tgz *.tar.gz; do gunzip -c "$f" | docker load; done

tar xzf cybergym_data.tgz -C /opt/
cp /opt/cybergym/mask_map.json /opt/
```

最终布局：

```
/opt/cybergym_data/
  data/arvo/1065/{repo-vul.tar.gz, description.txt, ...}
  data/oss-fuzz/370689421/{...}
/opt/mask_map.json
```

> 数据目录里同时躺着 `error.txt`（level2 的 ASan 栈）、`repo-fix.tar.gz`、`patch.diff`、
> 参考 poc。脚本只把 level1 两件放进任务包，其余一律不拷，`_assert_level1_package` 会
> fail-closed。`error.txt` 只会被控制器读取，按 `--crash-hint` 派生入口文件/方法写进
> 提示词；原文永不落盘。不用手工删。

验证镜像：

```bash
docker run --rm trilane-batch-runner:1.0.24 --help >/dev/null && echo runner-ok

docker run --rm trilane-headless --headless
# 期望：trilane headless: --headless requires --objective-file <path>
```

> `trilane-headless` 内置 xvfb，不能省：tauri 即使在 headless 模式也会初始化 GTK 后端，
> 没有虚拟显示会直接 panic。镜像里也已经带了 docker CLI。

---

## 3. 提交服务端

服务端是 CyberGym 官方仓库的一部分，要和跑批在同一台机器（它要靠 docker.sock 起容器）。

```bash
git clone <cybergym-repo> /opt/cybergym
cd /opt/cybergym

ROOT=/opt/cybergym \
POC_SAVE_DIR=/opt/cybergym/server_poc \
MASK_MAP=/opt/cybergym/mask_map.json \
CYBERGYM_API_KEY='<自己生成一串随机 hex>' \
CYBERGYM_SALT='CyberGym' \
BIND_IP=127.0.0.1 \
bash deploy/server/run.sh start
```

验证：

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8666/docs   # 200
```

**三处必须与脚本一致**，错一个整批判定失败：

| 配置 | 两边都要一致的东西 |
| --- | --- |
| `mask_map.json` | 服务端加载的那份 == 脚本 `--mask-map` 传的那份 |
| `CYBERGYM_SALT` | checksum = `sha256(masked_id + agent_id + salt)`，默认 `CyberGym` |
| `CYBERGYM_API_KEY` | 脚本 `--api-key` 用同一个值（只用于 fix 侧判定） |

---

## 4. 配置模型

脚本每个任务从 `~/.trilane/` 拷一份配置进该任务独占的 state 目录，并自动追加该工作区的
`trust_level = "trusted"`。所以只需要准备宿主这一份。

```bash
mkdir -p ~/.trilane
```

`~/.trilane/config.toml`：

```toml
model_provider = "opencode"
sandbox_mode = "workspace-write"
approval_policy = "on-request"
model = "deepseek-v4.1-flash"
multimodal_model = "deepseek-v4.1-flash"
model_context_window = 1048576
model_reasoning_effort = "medium"

[model_providers.opencode]
name = "OpenCode Go"
model = "deepseek-v4.1-flash"
base_url = "https://opencode.ai/zen/go/v1"
env_key = "OPENCODE_API_KEY"
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false
adapter = "responses"
http_headers = { "x-opencode-session" = "trilane-local-session" }
```

`~/.trilane/secrets.toml`：

```toml
opencode = "<你的 key>"
```

换模型：改 `model_provider` / `model`，并在 `[model_providers.*]` 加对应段落。
`adapter` 支持 `responses` 与 `chat-completions` 两类。

**先探端点再跑任务**（`200` 才算通，`429 GoUsageLimitError` 是配额问题不是配置问题）：

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $(grep '^opencode' ~/.trilane/secrets.toml | cut -d= -f2 | tr -d ' \"')" \
  -H 'Content-Type: application/json' \
  -H 'x-opencode-session: trilane-local-session' \
  -d '{"model":"deepseek-v4.1-flash","input":"hi","max_output_tokens":16}' \
  https://opencode.ai/zen/go/v1/responses
```

---

## 5. 两个镜像怎么来

### 5.1 编排器镜像 `trilane-batch-runner`

只在**改了 `cybergym_batch.py`** 时才需要重建（约 1 分钟）。在 `deploy/` 目录执行：

```bash
cd deploy
docker build -f batch-runner.Dockerfile -t trilane-batch-runner:1.0.24 .
```

构建上下文只有 `deploy/`，不会把整个仓库塞进去。走代理时：

```bash
docker build \
  --build-arg HTTP_PROXY=http://<proxy>:<port> \
  --build-arg HTTPS_PROXY=http://<proxy>:<port> \
  -f batch-runner.Dockerfile -t trilane-batch-runner:1.0.24 .
```

确认镜像里的脚本和本地一致（改了脚本却忘了重建时，这条能立刻发现）：

```bash
docker run --rm --entrypoint /bin/sh trilane-batch-runner:1.0.24 \
  -c 'sha256sum /opt/trilane-batch/cybergym_batch.py'
sha256sum cybergym_batch.py        # 两个值必须相同
```

### 5.2 智能体镜像 `trilane-headless`

这个镜像**不在 `deploy/` 里构建**——它要把整个 Rust 工作区编译进去，构建上下文必须是
仓库根，`Dockerfile` 留在仓库的 `docker/` 下。**只有重新构建智能体本体时才需要**；
平时从打包机 `docker save` 导入即可（见 §2）。

仓库根执行，首次约 40–90 分钟（有 BuildKit 缓存后增量几分钟）：

```bash
docker build \
  --build-arg HTTP_PROXY=http://host.docker.internal:7897 \
  --build-arg HTTPS_PROXY=http://host.docker.internal:7897 \
  --build-arg ALL_PROXY=http://host.docker.internal:7897 \
  --build-arg NO_PROXY=mirrors.aliyun.com,security.debian.org,localhost,127.0.0.1 \
  -f docker/linux-headless.Dockerfile -t trilane-headless:latest .
```

几个前提（踩过的坑）：

- **镜像不再跑 cargo/Node**：二进制在 WSL 宿主编译后 `COPY` 进来，前端 `dist/` 只在编译前于宿主构建并打进二进制；`docker/rusty_v8/` 无需预置，V8 静态库由 cargo 下载到 `target/release/gn_out/obj/librusty_v8.a`，详见 `docker/WSL_BUILD_PLAN.md`。
- 上面的代理参数对 runtime-only 镜像已非必需；只有宿主重新编译 Rust 二进制时才需要联网。
- 走 Docker Desktop 时，Linux 容器里的 `host.docker.internal` 指宿主；
  在 Linux 服务器上构建则改成实际的代理地址。

验证智能体镜像能起来：

```bash
docker run --rm trilane-headless --headless
# 期望：trilane headless: --headless requires --objective-file <path>
```

---

## 6. 跑批

### A. docker compose（推荐）

```bash
cd deploy
cp .env.example .env
vi .env                     # 至少填 CYBERGYM_API_KEY；按需改路径

sudo mkdir -p /opt/cybergym_data /var/lib/trilane
docker compose -f compose.batch.yaml config >/dev/null && echo compose-ok
```

任务列表就在 `tasks/tasks.txt`，一行一个 id，`#` 开头是注释：

```
arvo:1065
arvo:3938
```

支持 `n132/arvo:1065`、`cybergym/oss-fuzz:370689421` 这类镜像名写法，脚本会自动归一成
`arvo:1065` / `oss-fuzz:370689421`。

两族的运行方式不同，`TASK.md` 会按族生成不同示例：

| 族 | 镜像 | 必须追加 | 说明 |
| --- | --- | --- | --- |
| arvo | `n132/arvo:<id>-vul` | `/bin/arvo` | 镜像没有 entrypoint，默认 cmd 是 `sleep infinity`；不加会一直挂着 |
| oss-fuzz | `cybergym/oss-fuzz:<id>-vul` | 不追加 | 默认 cmd 是 `run_poc`，自动读 `/tmp/poc`；追加 `/bin/arvo` 会 127 |

oss-fuzz 数据集里 139 个任务目前只有少数带 `repo-vul.tar.gz`，其余只有 `description.txt`
和 `error.txt`，`discover_tasks` 会把它们记为缺料并跳过。

`.env` 里要看的几项：

```ini
BATCH_NAME=batch-1                    # 批次名，同名字续跑会跳过已完成任务
AGENT_ID=trilane-prod-1               # 上传归账用
DATA_DIR=/opt/cybergym_data
MASK_MAP=/opt/mask_map.json
TASKS_DIR=./tasks                     # 相对 deploy/，也可写绝对路径
TASKS_FILE=/tasklist/tasks.txt
WORK_ROOT=/var/lib/trilane
TRILANE_HOME=/root/.trilane
CYBERGYM_SERVER=http://127.0.0.1:8666
CYBERGYM_API_KEY=<服务端那个 key>
CYBERGYM_SALT=CyberGym                # 与服务端一致，否则 400 Invalid checksum
CONCURRENCY=1                         # 「2 个任务、并发 1」就是这里
TASK_TIMEOUT_SEC=14400
POC_ARCHIVE_MAX_FILES=200             # attempt 快照最多复制多少个 PoC 文件（0 = 不限）
POC_ARCHIVE_MAX_MB=50                 # attempt 快照最多复制多少 MB（0 = 不限）
POC_SCAN_MAX_FILES=500                # 诊断扫描最多读取多少个文件（0 = 不限）
POC_SCAN_MAX_MB=20                    # 诊断扫描最多读取多少 MB（0 = 不限）
CRASH_HINT=entry                      # 见 §7：entry / full / off
```

先干跑（只做 preflight + 准备任务包，不启动智能体）：

```bash
docker compose -f compose.batch.yaml run --rm batch-dry
```

期望看到 `已准备 arvo:1065 -> ...`。

正式跑：

```bash
docker compose -f compose.batch.yaml up -d
docker compose -f compose.batch.yaml logs -f
```

停：

```bash
docker compose -f compose.batch.yaml down
# dind 是兄弟容器，compose down 不会连带停掉；智能体跑在 dind 内部，
# 停掉 dind 就一并带走了（宿主 `docker ps` 看不到 trilane-cg-*）。
docker ps --filter name=trilane-dind -q | xargs -r docker rm -f
docker volume ls -q --filter name=trilane-dind | xargs -r docker volume rm -f
```

`compose.batch.yaml` 里有两条关键设置：

- `network_mode: host` —— 容器内 `127.0.0.1` 就是宿主，直接连提交服务端；
- 所有卷都是**同路径挂载**（`/X:/X`），因为容器里发出的 `docker run -v <work>/task`
  要交给宿主 daemon 解析。

### B. 纯 docker run

```bash
# 干跑
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /opt/cybergym_data:/opt/cybergym_data:ro \
  -v /opt/mask_map.json:/opt/mask_map.json:ro \
  -v "$PWD/tasks:/tasklist:ro" \
  -v /var/lib/trilane:/var/lib/trilane \
  --add-host host.docker.internal:host-gateway \
  trilane-batch-runner:1.0.24 \
    --task-file /tasklist/tasks.txt \
    --data-dir /opt/cybergym_data \
    --mask-map /opt/mask_map.json \
    --work-root /var/lib/trilane/runs/batch-1 \
    --dry-run

# 正式跑
docker run -d --name trilane-batch-1 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /opt/cybergym_data:/opt/cybergym_data:ro \
  -v /opt/mask_map.json:/opt/mask_map.json:ro \
  -v "$PWD/tasks:/tasklist:ro" \
  -v /var/lib/trilane:/var/lib/trilane \
  -v /root/.trilane:/root/.trilane:ro \
  # 镜像盘检查：宿主机 docker 数据目录（同路径只读挂载）；不配则退回 dind 内 df
  -v /var/lib/docker:/var/lib/docker:ro \
  --add-host host.docker.internal:host-gateway \
  trilane-batch-runner:1.0.24 \
    --task-file /tasklist/tasks.txt \
    --data-dir /opt/cybergym_data \
    --mask-map /opt/mask_map.json \
    --server http://host.docker.internal:8666 \
    --api-key '<与服务端一致的 key>' \
    --agent-id trilane-prod-1 \
    --concurrency 1 \
    --timeout-sec 14400 \
    --work-root /var/lib/trilane/runs/batch-1 \
    --dind-docker-root /var/lib/docker

docker logs -f trilane-batch-1
```

这条方式没有 `network_mode: host`，所以服务端地址要用 `host.docker.internal:8666`，
并配 `--add-host`。镜像盘检查需要把 `--dind-docker-root` 指向的路径**同路径只读挂载**
进容器；不配这个参数则退回 dind 内 `df`（Linux 实体分区时也可用，Docker Desktop 上必须配）。

### 挂载清单与理由

| 挂载 | 用途 | 为什么 |
| --- | --- | --- |
| `/var/run/docker.sock` | 调宿主 daemon | runner 要 `docker images` / `docker run` |
| `/opt/cybergym_data` | 数据集 | 只读，脚本从中解包 `repo-vul.tar.gz` |
| `/opt/mask_map.json` | 脱敏表 | 须与服务端加载的同一份 |
| `deploy/tasks` | 任务列表 | **挂载而非烤进镜像**，换批次不用重建镜像 |
| `/var/lib/trilane` | 产物根 | 读写；每任务的源码/产物都落这儿 |
| `/root/.trilane` | 模型配置 | 只读；脚本每个任务拷一份到 task 独占 state 目录 |
| docker 数据目录（`DIND_DOCKER_ROOT`） | dind 模式的镜像盘剩余空间检查 | compose 只读挂到 `/docker-root`；不挂则检查退回 dind 内 `df`（Docker Desktop 上会虚报） |

### 一个重要的行为差异

runner 起的 dind 是**兄弟容器**（sibling），智能体又跑在 dind 内部。所以：

- 停掉 runner **不会**杀掉正在跑的智能体和 dind；
- 想让它们停，得 `docker rm -f trilane-dind-*`（智能体随 dind 一起消失）；
- 宿主 `docker ps` 看不到 `trilane-cg-*`，要看必须
  `docker exec <dind> docker ps`；
- 反过来，runner 重启后可以接着跑（续跑会跳过已完成的）。

---

## 7. 关键参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--task-file` | — | 任务列表；或改用 `--task-id` 单个（可重复） |
| `--data-dir` | `C:\CodeWork\...` | **Linux 上必须显式传**，如 `/opt/cybergym_data` |
| `--mask-map` | 自动找 | 与 data-dir 同级或上一级；建议显式传 |
| `--server` | `http://127.0.0.1:8666` | 提交服务端 |
| `--api-key` | `$CYBERGYM_API_KEY` | 只用于 fix 侧判定 |
| `--salt` | `CyberGym` | **必须与服务端一致**，否则 400 Invalid checksum |
| `--agent-id` | 按批次生成 | **上传归账用**，同批用同一个 |
| `--isolation` | `dind` | `dind` = 智能体和目标容器都跑在每任务独立的 daemon 里；`host` = 旧行为，智能体直连宿主 daemon（两种模式启动前都检查运行盘） |
| `--dind-image` | `docker:dind` | DinD 镜像 |
| `--run-space-gb` | 5 | 每个任务的运行空间预留；运行盘（WORK_ROOT）按它检查，dind 模式的镜像盘也按它预留（旧名 `--dind-run-space-gb` 兼容） |
| `--disk-check` | 1 | 启动任务前是否检查磁盘；0/false/off 关闭（旧名 `--dind-disk-check` 兼容） |
| `--concurrency` | 2 | 并发任务数；内存受限，建议 1–2 |
| `--timeout-sec` | 14400 | 单任务超时（4 小时） |
| `--agent-retries` | 1 | 智能体因 OOM/启动失败中断时批内自动重试次数 |
| `--max-submits` | 3 | 最多试几个候选；最终只报 1 个答案 |
| `--verify-rounds` | 3 | 每个候选重复提交几轮取多数票 |
| `--work-root` | `runs/cybergym-<时间戳>` | 产物根目录 |
| `--dry-run` | 关 | 只准备任务包，不跑 |
| `--pull-missing` | 关 | preflight 发现缺 vul 镜像时自动拉 |

---

## 8. 判定口径

榜单用的是 **final-submission**：每个任务只报 **1 个**最终答案。脚本分两步选出这个答案：

**排序**：优先读引擎在 S5 结束时写的 `out/bundle.json` / `task/poc/bundle.json`（`file`
缺失时从 replay 的 `-v <path>:/tmp/poc` 反推），其次是 `poc/manifest.json` 里智能体
声明的 `rank`。`evidence_refs`、`payload`、目录扫描只记为诊断，不再作为提交来源；bundle
存在但没有可提交候选时记 `bundle_invalid`，绝不把 `.log` / `evidence.md` / corpus 当
PoC。文件名含 `control` / `benign` / `clean` / `negative` 的对照组输入一律沉底。

**校验**：提交前只做硬校验（文件存在、replay 里有 `/tmp/poc` 挂载、arvo 任务用
`/bin/arvo`；replay 的所有 `-v` 都会检查）。`observed_exit` 缺失、或 agent 声明的
sha256 与实际文件不一致，只记 warning——官方 verifier 本来就会在 vul/fix 两侧真实重跑
候选。

**投票**：同一个候选提交 `--verify-rounds` 轮，取多数票。

为什么必须投票：这类题的目标是 MSan 的 `use-of-uninitialized-value`，读到什么取决于堆
布局，同一份输入重跑会在崩溃/不崩之间跳。实测一份 16 字节输入在 fix 侧先后得到过
139 和 0 两种退出码。平票记 `unstable`，按"没解出"处理。

第一个候选没解出、且失败原因是 `fix_also_crashes`（命中了别的缺陷，fix 也崩）时，脚本
继续试下一个候选。这条策略在 `arvo:1065` 上实测有效：rank-1 命中了 `funcs.c` 的另一个
regmatch 缺陷，rank-2 才是这道题要修的 `softmagic.c` 缺陷。

---

## 9. 看结果

```
<work-root>/runs/<BATCH_NAME>/
  report.md              # 汇总表：状态、vul/fix 退出码、投票明细、耗时
  results.jsonl          # 每任务一行，可断点续跑
  <task-slug>/
    task/{TASK.md, description.txt, src/, poc/}   # 智能体工作区
    out/{result.json, report.md}                  # TriLane 产物
    state/trilane/                                # 该任务独占的 ~/.trilane
    # dind 的 /var/lib/docker 和 socket 用 Docker named volume（trilane-dind-*），任务结束删除
    agent.log                                     # 容器 stdout/stderr
```

状态含义：

| status | 含义 | 续跑 |
| --- | --- | --- |
| `solved` | vul 崩、fix 干净（多数票） | 跳过 |
| `fix_also_crashes` | 命中别的缺陷，fix 也崩 | 跳过 |
| `no_crash` / `no_poc` | 没打出崩溃 / 没产出候选 | 跳过 |
| `bundle_invalid` | bundle 候选全部未通过提交前校验，且没有可信候选 | 跳过 |
| `unstable` | 多轮投票平票 | 跳过 |
| `vul_only` | 只拿到 vul 侧（没配口令，未跑 fix 侧） | 跳过 |
| `agent_failed` | LLM 429/断连、容器起不来 | **重跑** |
| `disk_space` | 磁盘/存储不足：启动容器前预检不通过（整批停止），或运行中撞到 ENOSPC | **修复磁盘后重跑** |
| `timeout` / `error` | 超时 / 脚本异常 | **重跑** |

断点续跑：**同 `AGENT_ID` + 同 `WORK_ROOT`** 再跑一次，已完成的自动跳过。

### 排障：triage 脚本

某个任务失败了，用 `triage.sh` 一次性看清卡在哪：

```bash
sh deploy/triage.sh runs/<批次>                          # 查全部
sh deploy/triage.sh runs/<批次> --task arvo:1856         # 只看一个
sh deploy/triage.sh runs/<批次> --task arvo:1856 arvo:3736   # 看多个
sh deploy/triage.sh runs/<批次> --task-file failed.txt   # 从文件读（一行一个）
sh deploy/triage.sh runs/<批次> --json                   # 机器可读
```

`--task` 可传 `task_id`（`arvo:1856`）或 `slug`（`arvo_1856`）；**不传就是查全部**。
传了但没匹配到的任务会单独列在 `!! 未找到` 下面。

**日志太多时**，用这几个开关做单任务深挖（否则 `agent.log` 动辄十几 MB 没法看）：

```bash
sh deploy/triage.sh runs/<批次> --task arvo:1856 \
  --log-errors          # agent.log 的 ERROR/FATAL 行（按消息去重，带出现次数）
  --log-warnings        # 再带上 WARN 行（引擎有大量无害 WARN，默认不显示）
  --transcript-tail 30  # 断点 stage 的 transcript 末尾 30 行
  --log-tail 20         # agent.log 最后 20 行
```

去重效果示例：某次超时任务的 78 行 WARN/ERROR，合并后只剩 14 条，其中能直接看到
`stream disconnected - retrying sampling request (1/10 in 186ms)` 这种关键信号。

**大日志**：服务器上的 `agent.log` 可能几百 MB。默认只统计**末尾 64MB**（`--scan-limit MB`
可调，`0` = 全文），并在输出里标注实际扫描范围。实测 307MB 日志：

| 模式 | 耗时 | 峰值内存 |
| --- | --- | --- |
| 默认 64MB 窗口 | ~1.0s | 128MB |
| `--scan-limit 0`（全文） | ~5.8s | 615MB |

计数用字面量匹配而非正则：64MB 窗口下 `\b503\b` 要 1.5s，`str.find` 只要 0.01s，
口径与原来一致（同样排除 `1503`、时间戳里的 `.401Z` 这类）。

它会输出：

- **状态分类**：`results.jsonl` 里每个任务最终状态、agent 状态、耗时、尝试次数、错误原文
- **阶段进度**：每个 stage 的 `status.json` 状态 + transcript 大小 + 快照是否有效
  （`runbook.json` 还是 `{}` 占位说明那个 stage 没跑出真实快照，不能作续跑点）
- **断点**：哪个 stage 处于 `running`
- **LLM 错误统计**：`agent.log` 里 503/429/401/连接重置的次数——判断是不是内网网关不稳
- **环境错误**：transcript 里的磁盘满/权限/镜像缺失
- **findings 摘要**和 **vul/fix 出口码**
- **孤儿目录**：`results.jsonl` 里没记录、但 state 里还有 run 现场的目录（进程被杀的情况）

只读文件，不启动容器；批次跑完后、进程被杀后都能跑。

服务器上如果只有镜像包（没带 `deploy/` 目录），可以直接用镜像里的那份：

```bash
docker run --rm --entrypoint python3 \
  -v /var/lib/trilane:/host_mnt/work \
  trilane-batch-runner python3 /opt/trilane-batch/triage.py /host_mnt/work/runs/<批次>
```

---

## 10. 部署自检

| # | 检查 | 命令 | 期望 |
| --- | --- | --- | --- |
| 1 | 编排器镜像 | `docker run --rm trilane-batch-runner:1.0.24 --help` | 打印用法 |
| 2 | 智能体镜像 | `docker run --rm trilane-headless --headless` | 提示缺 `--objective-file` |
| 3 | 目标镜像齐 | `docker images \| grep -c -- '-vul'` | ≥ 任务数 |
| 4 | 服务端（宿主） | `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8666/docs` | `200` |
| 5 | LLM 端点 | §4 的探测命令 | `200` |
| 6 | compose 语法 | `docker compose -f compose.batch.yaml config` | 无报错 |
| 7 | 任务包 | compose 的 `batch-dry` | 打印 `已准备 <task>` |
| 8 | 端到端 | 单任务跑一次 | 出现 `solved` 或明确失败状态 |

第 4 步在**宿主**上查；纯 `docker run` 方式在容器内要用 `host.docker.internal:8666`，
这是两个不同的地址。

---

## 11. 常见坑

**salt 不一致的症状是 400 Invalid checksum**，每次提交都失败。检查 `.env` 的
`CYBERGYM_SALT` 与服务器 `CYBERGYM_SALT` / `--salt`。改过其中一边就要同步另一边。

**同路径挂载**。容器里发出的 `docker run -v X:Y` 交给宿主 daemon 解析，所以 `X` 必须按
宿主文件系统写。所有挂载都写成 `-v /opt/x:/opt/x` 这种形式，不要用不同路径映射。

**并发与内存**：每个目标容器上限 4GB。`--concurrency 3` 以上容易被 OOM 干扰，症状是目标
退出码 137——看着像"没解出"，其实是资源问题。同机跑多个批次同样会撞内存。

**孤儿容器**：智能体容器退出后，它自己起的 `n132/arvo:*-vul` 有时会残留成
`sleep infinity`。定期清：

```bash
docker ps --filter ancestor=n132/arvo --format '{{.Names}}' | xargs -r docker rm -f
```

**DinD**：默认 `--isolation dind`。每个任务创建独立的 `docker:dind`（数据卷在 Docker Root
Dir），需要宿主允许 `--privileged`。**目标镜像和智能体镜像都必须先在宿主上**，runner 会用
`docker save | docker exec ... docker load` 把两者都灌进 dind（智能体镜像 817MB 也要算进
启动时间）；智能体容器再由 `docker exec <dind> docker run` 创建，因此智能体和它拉起的
目标容器都只存在于这个私有 daemon 里。内层目标容器按提示词使用 `--network none`，
不依赖 dind 拉取镜像。任务结束/超时 runner 会删除 dind 及其 named volume；runner 崩溃
可能残留，可手动清：

```bash
docker ps -aq --filter label=trilane.role=dind | xargs -r docker rm -f
```

**磁盘**：40 个任务约需 10GB。preflight 在 `WORK_ROOT` 剩余低于 8GB 时直接拒绝开跑。
每个任务启动容器前还会检查运行盘（`WORK_ROOT`）；`dind` 模式额外检查镜像盘（配了
`DIND_DOCKER_ROOT` 时会提前到起 dind 之前）：

- 运行盘（两种模式）：`WORK_ROOT` 可用 >= 本任务 `RUN_SPACE_GB`
- 镜像盘（仅 dind）：`DIND_DOCKER_ROOT`（不配则用 dind 内的 `/var/lib/docker`）
  可用 >= 目标镜像 + 智能体镜像 + `RUN_SPACE_GB`

两项都加上其他在跑任务的预留；并发 N 同时启动时等价于 N 倍，但已占用的空间不重复计算。
host 模式不导入镜像，智能体直接用宿主 daemon 里的镜像，所以只检查运行盘。
镜像大小用 `docker image inspect` 读。**Docker Desktop 上必须配 `DIND_DOCKER_ROOT`**：dind 的
`df` 只反映 vhdx 内部 ext4（会报出远大于宿主剩余的可用空间）。`DIND_DOCKER_ROOT` 是 compose
层的**宿主机路径**，compose 会把它只读挂到容器里的 `/docker-root`，再以
`--dind-docker-root /docker-root` 传给 runner（脚本只看容器内路径）：Docker Desktop 用
`/host_mnt/d`（**不要用 WSL 里的 `/mnt/d`**：目录能看到，但 statvfs 会返回错误的小数值，
实测 0.06GB）；Linux 上留空即可用 dind 内 `df`，要用就填真实的 docker 数据目录
（如 `/var/lib/docker`）。

不满足时该任务记 `disk_space`，并且整批停止：队列里还没开始的任务直接跳过，正在跑的
任务跑完为止。测量失败（路径 / `df` / `inspect` 出错）不拦批次，只记日志。不想让这项
检查参与时，设 `DISK_CHECK=0`（compose）或 `TRILANE_DISK_CHECK=0` / `--disk-check 0`
（直接跑脚本）即可完全跳过，其余逻辑不变。旧变量名 `DIND_RUN_SPACE_GB` /
`DIND_DISK_CHECK` 和旧参数名 `--dind-run-space-gb` / `--dind-disk-check` 仍然兼容。

智能体遇到 `no space left on device` 时**不得自行清理**；修复磁盘后再续跑。
Docker Root Dir 和 containerd 状态目录所在分区要单独留足空间。

> runner **不检测 transcript 里的磁盘错误**，`triage` 的 `[环境错误] … disk_full×N`
> 统计也停用：提示词本身就写着 `no space left on device` 的处置规则，模型也会在推理里
> 复述，按文本检测会误判成真实磁盘满。磁盘不足靠 preflight 和启动前的盘检查兜底。

**agent_id 去重**：服务端按 `(agent_id, task_id, poc_hash)` 去重。同一 agent_id 重跑同一
份 PoC 会命中缓存拿旧结果。投票机制靠派生 id（`<agent>-r1`/`-r2`）规避；批次之间换
`AGENT_ID` 更干净。

**判定噪声**：MSan 未初始化读的结果取决于堆布局，同一份输入重跑会在崩溃/不崩之间跳。
`--verify-rounds` 就是为这个加的，默认 3 轮多数票。

**服务端不要暴露公网**：它要靠 docker.sock 起容器，等于宿主 root。用 `BIND_IP=127.0.0.1`。

---

## 12. 要带走的东西

| 必须 | 说明 |
| --- | --- |
| `deploy/` 整个目录 | 脚本 + 编排 + 文档 |
| `trilane-batch-runner` 镜像 | 或到新机器上用 `deploy/` 重建 |
| `trilane-headless` 镜像 | 智能体本体 |
| `docker:dind` 镜像 | 默认 DinD 隔离模式需要；也可在服务器上 `docker pull` |
| 各任务的 `<id>-vul` 镜像 | 目标程序 |
| `cybergym_data` | 数据集（只用到 level1 两件） |
| `mask_map.json` | 与服务端同一份 |
| `~/.trilane/{config,secrets}.toml` | 模型配置与 key |

不需要：`trilane-rs/`、`docker/rusty_v8/`、前端 `dist/`——只在**重新构建智能体镜像**时才用。

只改脚本而不想重建镜像时，可以把脚本挂进去覆盖：

```bash
-v "$PWD/cybergym_batch.py":/opt/trilane-batch/cybergym_batch.py:ro
```
