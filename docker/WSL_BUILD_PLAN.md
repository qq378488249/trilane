# WSL 宿主机构建 + 精简镜像方案（待执行）

目标：在 WSL Ubuntu 24.04 里编译 `trilane-gui`，只把生成的单个二进制拷进镜像；镜像退化为纯 runtime 层，不再在容器里跑 cargo-chef / Rust 编译。
Windows 上的 `D:\CodeWork\trilane` 在验证通过前保持不动，所有改动发生在 WSL 副本的新分支里。

## 已实测的环境事实（2026-11-24）

- WSL 默认发行版 Ubuntu 24.04.1，glibc 2.39，16 核，约 9GB 可用内存，`/` 剩余 936GB。
- Windows 侧 Docker CLI 29.9.2 可用，但 daemon 当前未运行；WSL Ubuntu 尚未开启 Docker WSL 集成（`docker --version` 会提示开启集成）。
- WSL 的 rustup 1.28.1 可用，但 `stable` 工具链的 `rustc` 是 **0 字节**文件（坏安装），也没有项目要求的 1.95.0；最小 crate 编译报 `Exec format error`。
- 网络可用：经 `127.0.0.1:7897` 代理，`static.rust-lang.org`、`index.crates.io`、`github.com` 均返回 200。
- WSL 里的 `node` 是 Windows 的 shim，执行失败；`npm` 是 10.9.2。Windows 侧 `trilane-rs/trilane-gui/frontend/dist/` 当前**不存在**。
- `docker/rusty_v8/`、`docker/cargo-git/` 两个 gitignore 的缓存目录当前都不存在；`D:\cargo\git\db` 也不存在，Dockerfile 里的预置说明已过时。
- 源码树约 65MB；`/home/loong/codeWork` 已存在（里面有别的项目），目标目录用 `trilane`。

## 关键决策

1. **runtime 基础镜像从 `debian:bookworm-slim` 改为 `ubuntu:24.04`**：与 WSL 构建环境同代（glibc 2.39、webkit2gtk 2.52.6），避免编出来的二进制在旧镜像里报 `GLIBC_2.38 not found` 或 WebKit 符号缺失。代价：镜像略大，apt 源配置文件路径从 `debian.sources` 改为 `ubuntu.sources`。
2. **SOP 路径改成运行时查找**：不再依赖编译期固化的 `env!("CARGO_MANIFEST_DIR")`，但保留它作为开发机回退。
3. **只改 WSL 副本**：新分支 `build/wsl-headless`；Windows 工作区等验证通过后再接收 patch。

## 执行步骤

### 0. 准备 Docker

启动 Docker Desktop，在 Settings → Resources → WSL Integration 勾选 Ubuntu，然后在 WSL 里确认 `docker info` 能连上 daemon。
备选：不开集成，最后把二进制拷回 Windows，用 Windows 侧的 `docker build` 构建镜像（只是多一次文件复制）。

### 1. 拷贝源码并开分支（在 WSL 里）

```bash
cp -a /mnt/d/CodeWork/trilane /home/loong/codeWork/trilane
cd /home/loong/codeWork/trilane
git switch -c build/wsl-headless
git status --short          # 应为空
```

仓库里没有 `target/`，拷贝很轻。WSL 全局 git user.name/email 未配置；如需在分支上提交，先用 `git config user.name ...` / `git config user.email ...` 设置仓库级身份。

### 2. 修复 Rust 工具链

```bash
rustup toolchain install 1.95.0 --profile minimal \
  --component clippy --component rustfmt --component rust-src
rustup default 1.95.0
rustc -vV                   # 必须是 1.95.0
```

如果坏的 `stable` 工具链仍碍事：`rustup toolchain uninstall stable`。项目根目录的 `rust-toolchain.toml` 钉的就是 1.95.0，装好后 `cargo` 会自动选中它。

### 3. 安装编译依赖（Ubuntu noble）

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev \
  libjavascriptcoregtk-4.1-dev librsvg2-dev \
  libayatana-appindicator3-dev pkg-config build-essential
```

构建前记录版本（例如 `dpkg-query -W libwebkit2gtk-4.1-dev`）；runtime 镜像的 apt 会装同源最新版，若版本漂移导致启动失败，要么把镜像 apt 固定到同一版本，要么重编二进制。

### 4. 先构建前端 dist

Tauri 的 `frontendDist` 是 `./frontend/dist`（`trilane-rs/trilane-gui/tauri.conf.json:7`），缺失会打出空前端。二选一：

- Windows 侧：`cd trilane-rs/trilane-gui/frontend && npm install && npm run build`，dist 通过 `/mnt/d` 对 WSL 可见；
- WSL 侧：用 nvm 装 Linux Node 20+，再执行同样的 npm 命令（系统 PATH 里的 `node` 是坏 shim，不要用）。

确认 `trilane-rs/trilane-gui/frontend/dist/index.html` 存在后再往下走。

### 5. 改 SOP 路径（新分支内的代码改动）

文件：`trilane-rs/trilane-gui/src/main_commands.inc.rs:73`，把

```rust
let sop_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("sop/system_prompt_v4.md");
```

改成：

```rust
let sop_path = std::env::var_os("TRILANE_SOP_PATH")
    .map(std::path::PathBuf::from)
    .unwrap_or_else(|| {
        let container =
            std::path::PathBuf::from("/src/trilane-rs/trilane-gui/sop/system_prompt_v4.md");
        if container.exists() {
            container
        } else {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("sop/system_prompt_v4.md")
        }
    });
```

开发机仍走原来的 `CARGO_MANIFEST_DIR` 回退；容器里读到镜像 COPY 进去的固定路径。现有日志会打印实际路径和字节数，方便验证是否命中。

### 6. WSL 里编译并导出二进制

```bash
cd /home/loong/codeWork/trilane/trilane-rs
export CARGO_BUILD_JOBS=4
export CARGO_PROFILE_RELEASE_LTO=thin
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=4
cargo build -p trilane-gui --release --locked
mkdir -p ../docker/bin
cp target/release/trilane-gui ../docker/bin/trilane-gui
```

- `jobs=4` 对 16 核 / 9GB 是保守值；内存吃紧就降到 2。不再需要原来容器里的 `jobs=1` 和 `cargo clean -p trilane-gui`。
- `v8 = "=147.4.0"` 的 build script 只把 `~/.cargo/.rusty_v8/` 当作**可选的离线输入目录**，不会创建它。首次构建从 GitHub 下载预编译静态库（GitHub 已验证可达），解压到 `target/release/gn_out/obj/librusty_v8.a`，同目录的 `.sum` 记录下载 URL；URL 不变就复用，不需要 `docker/rusty_v8/`。
- 下载失败时可用 `RUSTY_V8_MIRROR` 指向镜像，或把 `librusty_v8_release_x86_64-unknown-linux-gnu.a.gz` 按转义后的 URL 文件名放进 `$CARGO_HOME/.rusty_v8/`（确切文件名见构建日志里的 `Looking for download in ...`）。

### 7. 精简 Dockerfile

`docker/linux-headless.Dockerfile` 只保留 runtime 阶段，删除 chef / planner / builder 三段以及 proxy、git bare repo、V8、cargo-chef 的全部逻辑：

```dockerfile
# syntax=docker/dockerfile:1.7
FROM docker.1ms.run/library/ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i 's|http://archive.ubuntu.com/ubuntu/|http://mirrors.huaweicloud.com/ubuntu/|g; s|http://security.ubuntu.com/ubuntu/|http://mirrors.huaweicloud.com/ubuntu/|g' \
      /etc/apt/sources.list.d/ubuntu.sources \
 && apt-get update && apt-get install -y --no-install-recommends \
      libwebkit2gtk-4.1-0 libgtk-3-0 libsoup-3.0-0 libjavascriptcoregtk-4.1-0 \
      libayatana-appindicator3-1 librsvg2-2 \
      ca-certificates bash xvfb xauth \
      ripgrep python3 xxd file jq curl binutils bsdextrautils \
    && rm -rf /var/lib/apt/lists/*
COPY --from=docker.1ms.run/library/docker:cli /usr/local/bin/docker /usr/local/bin/docker
COPY --chmod=755 docker/bin/trilane-gui /usr/local/bin/trilane-gui
COPY trilane-rs/trilane-gui/sop/ /src/trilane-rs/trilane-gui/sop/
ENTRYPOINT ["/bin/sh", "-c", "xvfb-run -a /usr/local/bin/trilane-gui \"$@\"", "--"]
CMD ["--headless"]
```

注意两点：`--chmod=755` 避免单独的 `RUN chmod` 把 197MB 二进制再复制出一层（实测镜像从 1.12GB 降到 915MB）；apt 源用 HTTP 华为云，因为基础镜像里还没有 `ca-certificates`，HTTPS 镜像会报证书不受信任，而阿里云的 `noble/universe/Packages` 索引连接失败。

同时新增 `.dockerignore`，排除 `.git/`、`**/target/`、`**/node_modules/`、`docker/*.tar.gz`、`docker/cargo-git/`、`docker/rusty_v8/`、`deploy/images/`，只把源码、SOP、dist 和那一个二进制送进构建上下文。

构建：

```bash
cd /home/loong/codeWork/trilane
docker build -f docker/linux-headless.Dockerfile -t trilane-headless .
```

若在 Windows 侧构建，先把 `docker/bin/trilane-gui` 拷回 `D:\CodeWork\trilane\docker\bin\`。

### 8. 验证

1. `ldd docker/bin/trilane-gui` 不应出现 `not found`。
2. `objdump -T docker/bin/trilane-gui | grep GLIBC_`，最高版本不超过 2.39。
3. 跑一个最小任务，日志必须出现 `SOP loaded: ... from /src/trilane-rs/trilane-gui/sop/system_prompt_v4.md`；出现 `SOP not loaded` 即为失败。
4. 容器内确认 `xvfb-run` 入口正常，`docker --version`、`rg`、`python3`、`jq`、`curl` 可用。
5. 导出镜像包：`docker save trilane-headless | gzip > deploy/images/trilane-headless.tgz`（gitignore 已覆盖该目录）。

## 交付与回滚

- 验证通过前 Windows 工作区不动；WSL 副本随时可丢弃：`git switch main && git branch -D build/wsl-headless`。
- 验证通过后，把 WSL 分支的改动（`main_commands.inc.rs`、`linux-headless.Dockerfile`、`.dockerignore`）以 patch 形式应用到 Windows 工作区，是否提交由用户决定。
- 二进制和镜像包不进 git。

## 风险与备选

| 风险 | 处理 |
| --- | --- |
| Ubuntu 24.04 镜像的 WebKit 版本与 WSL 构建机漂移 | 固定镜像 apt 到构建机的版本，或把构建环境换成 Debian bookworm 并把 runtime 改回 `bookworm-slim` |
| Docker WSL 集成不方便开 | 在 Windows 侧 `docker build`，只多一次二进制复制 |
| V8 静态库下载失败 | `RUSTY_V8_MIRROR`，或把 `.a.gz` 按转义 URL 文件名放到 `$CARGO_HOME/.rusty_v8/`；保留 `target/` 可直接复用已解压的静态库 |
| 前端 dist 缺失导致空界面 | 第 4 步强制检查 `dist/index.html` |
| 容器里 SOP 静默退化 | 第 8 步强制检查日志中的 `SOP loaded` 行 |

## 预期收益

镜像构建阶段只剩 apt 安装和几个 `COPY`，从原来的 40~90 分钟降到分钟级；Rust 编译走 WSL 的 16 核和持久 cargo 缓存，后续改源码只需重跑第 6、7 步。

## 执行结果（2026-11-24）

- 已在 WSL 完成拷贝、新分支、工具链修复、依赖安装、前端构建、SOP 改动和 `cargo build -p trilane-gui --release --locked`；二进制 205,598,640 字节，`ldd` 无缺失，最高 `GLIBC_2.39`。
- 期间 Docker Desktop 连续三次因 `sailor-ingest.sock` 的 AF_UNIX bind 错误崩溃，用户手动重启后 daemon 恢复；apt 源先后尝试阿里云（索引连接失败）和腾讯云 HTTPS（证书不受信任），最终华为云 HTTP 可用。
- 镜像 `trilane-headless:latest` 构建成功：去掉重复二进制层后 915MB。验证结果：`docker run --rm trilane-headless --headless` 正常启动 xvfb 并输出 `--headless requires --objective-file <path>`；容器内 SOP 文件位于 `/src/trilane-rs/trilane-gui/sop/system_prompt_v4.md`，`ldd` 无缺失，docker CLI / rg / python3 / jq / curl / xvfb-run 均在。
- **未验证**：真实跑批时的 `SOP loaded` 日志（需要 objective 文件和模型调用）；`strip` 无效（201MB 是代码段，V8 静态库），未再尝试删图标/文档。
- V8 库由 GitHub 下载后解压在 `target/release/gn_out/obj/librusty_v8.a`（163MB），`~/.cargo/.rusty_v8/` 未生成（正常）；WSL 编译以 loong 用户（uid 1000）执行，产物均属 loong。
- Windows 工作区改动：`.dockerignore`、`.gitignore`、`docker/linux-headless.Dockerfile`、本文档；WSL 分支 `build/wsl-headless` 额外含 `main_commands.inc.rs` 的 SOP 改动。均未提交。
- 原 `docker/headless.Dockerfile` 已恢复为 git 中的旧版多阶段构建；WSL 编译版只保留在 `docker/linux-headless.Dockerfile`。
