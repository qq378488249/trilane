# TriLane headless 镜像
# 构建（在仓库根执行，约 40~90 分钟，BuildKit 缓存后增量）：
#   docker build -f docker/headless.Dockerfile -t trilane-headless .
# 运行示例：
#   docker run --rm \
#     -v /var/run/docker.sock:/var/run/docker.sock \
#     -v <task_dir>:/task \
#     -v <out_dir>:/out \
#     -v <home_dir>:/root/.trilane \
#     trilane-headless \
#     --objective-file /task/TASK.md --out-dir /out --cwd /task/workspace \
#     --audit-mode lab --headless-timeout-sec 3600

# syntax=docker/dockerfile:1.7

# ---------- chef base ----------
FROM docker.1ms.run/library/rust:1.95-bookworm AS chef
ENV DEBIAN_FRONTEND=noninteractive
# trilane-rs/rust-toolchain.toml 声明了 clippy/rustfmt/rust-src，基础镜像只装了
# cargo/rustc/rust-std；不指定 RUSTUP_TOOLCHAIN 时 rustup 会去 static.rust-lang.org
# 同步 channel 补组件，容器内无外网就构建失败。构建不需要这些组件，直接绕过。
ENV RUSTUP_TOOLCHAIN=1.95.0
RUN sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources \
 && apt-get update && apt-get install -y --no-install-recommends \
      libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev \
      libjavascriptcoregtk-4.1-dev librsvg2-dev libayatana-appindicator3-dev \
      pkg-config build-essential \
    && rm -rf /var/lib/apt/lists/*

# cargo-chef 把依赖编译和源码编译拆开：只改 SOP/源码时，依赖层可以命中缓存。
# 代理下 crates.io 偶发 SSL EOF；关掉 HTTP/2 multiplexing 并加大重试。
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    CARGO_NET_RETRY=10 CARGO_HTTP_TIMEOUT=120 CARGO_HTTP_MULTIPLEXING=false \
    cargo install cargo-chef --locked

# 显式转成小写代理变量，供 git/libcurl 使用；只存在于 builder 阶段，
# 不会进入最终 runtime 镜像。
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG ALL_PROXY
ARG NO_PROXY
ENV http_proxy=$HTTP_PROXY https_proxy=$HTTPS_PROXY all_proxy=$ALL_PROXY no_proxy=$NO_PROXY

# 代理下 git 的 HTTP/2 会偶发 GnuTLS 解码错误，强制 HTTP/1.1。
RUN git config --system http.version HTTP/1.1

# 预置 git 依赖的 bare repo，避免构建期访问 GitHub。
# 来源：宿主 D:\cargo\git\db（Windows release 构建时已克隆好）。
COPY docker/cargo-git/db /tmp/cargo-git-db
RUN --mount=type=cache,target=/usr/local/cargo/git \
    cp -a /tmp/cargo-git-db/. /usr/local/cargo/git/db/ \
 && rm -rf /tmp/cargo-git-db

# git 依赖已在 cache mount 里；registry 还缺少量 crate，fetch 阶段允许联网补齐。
WORKDIR /src

# ---------- planner ----------
FROM chef AS planner
COPY trilane-rs/ trilane-rs/
# 先把所有依赖（含 crossterm 这类 git 依赖）拉进持久化的 cargo git cache。
# 代理下 GitHub 克隆会偶发 SSL EOF；用 git CLI + 重试 + 缓存，避免每次构建重来。
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cd trilane-rs && \
    env CARGO_NET_RETRY=10 CARGO_HTTP_TIMEOUT=120 CARGO_HTTP_MULTIPLEXING=false \
        CARGO_NET_GIT_FETCH_WITH_CLI=true GIT_TERMINAL_PROMPT=0 \
        cargo fetch --locked --target x86_64-unknown-linux-gnu
RUN cd trilane-rs && cargo chef prepare --recipe-path recipe.json

# ---------- builder ----------
FROM chef AS builder
# 先只喂依赖清单：依赖编译结果与源码解耦。
COPY --from=planner /src/trilane-rs/recipe.json /src/trilane-rs/recipe.json
# 前端 dist 在宿主上构建（平台无关），镜像内不需要 Node
COPY trilane-rs/trilane-gui/frontend/dist/ trilane-rs/trilane-gui/frontend/dist/
# 预置 rusty_v8 静态库，避免构建时访问 GitHub
COPY docker/rusty_v8/ /usr/local/cargo/.rusty_v8/

ENV CARGO_BUILD_JOBS=1
# headless 镜像不需要 fat LTO；thin + 多 codegen units 能显著缩短最终链接。
# 4 而不是 16 是为了控制这台 7GB 机器的内存峰值。
ENV CARGO_PROFILE_RELEASE_LTO=thin
ENV CARGO_PROFILE_RELEASE_CODEGEN_UNITS=4
WORKDIR /src/trilane-rs
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/trilane-rs/target \
    CARGO_NET_OFFLINE=true CARGO_NET_RETRY=10 CARGO_HTTP_TIMEOUT=120 CARGO_HTTP_MULTIPLEXING=false \
    CARGO_NET_GIT_FETCH_WITH_CLI=true GIT_TERMINAL_PROMPT=0 \
    http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" all_proxy="$ALL_PROXY" \
    cargo chef cook --release --recipe-path recipe.json

# 依赖就绪后再复制真实源码，只编译 workspace 自己的 crate。
# 注意必须用绝对目标路径：当前 WORKDIR 是 /src/trilane-rs，相对写法会变成
# /src/trilane-rs/trilane-rs，导致最终 build 仍然编译 cargo-chef 的 dummy 源码。
COPY trilane-rs/ /src/trilane-rs/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/trilane-rs/target \
    CARGO_NET_RETRY=10 CARGO_HTTP_TIMEOUT=120 CARGO_HTTP_MULTIPLEXING=false \
    CARGO_NET_GIT_FETCH_WITH_CLI=true GIT_TERMINAL_PROMPT=0 \
    http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" all_proxy="$ALL_PROXY" \
    cargo clean -p trilane-gui --release \
 && cargo build -p trilane-gui --release --offline \
 && cp target/release/trilane-gui /usr/local/bin/trilane-gui

# ---------- runtime ----------
FROM docker.1ms.run/library/debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
# 运行期没有外网，智能体需要的工具必须在构建期装好。transcript 里
# rg/python3/xxd/hexdump/file/curl 都出现过 command not found，模型只能退回
# find/perl/od/printf，既慢又浪费回合。
RUN sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources \
 && apt-get update && apt-get install -y --no-install-recommends \
      libwebkit2gtk-4.1-0 libgtk-3-0 libsoup-3.0-0 libjavascriptcoregtk-4.1-0 \
      ca-certificates bash \
      xvfb xauth \
      ripgrep python3 xxd file jq curl binutils bsdextrautils \
    && rm -rf /var/lib/apt/lists/*

# docker CLI：默认连每任务 DinD 的 socket（--isolation host 时才连宿主 daemon）
COPY --from=docker.1ms.run/library/docker:cli /usr/local/bin/docker /usr/local/bin/docker

COPY --from=builder /usr/local/bin/trilane-gui /usr/local/bin/trilane-gui
# system_prompt_v4.md 是运行时按编译期 CARGO_MANIFEST_DIR 路径读取的
# （main_commands.inc.rs），路径必须与构建时源码布局一致；缺失会静默退化成兜底短语。
COPY trilane-rs/trilane-gui/sop/ /src/trilane-rs/trilane-gui/sop/
# headless 模式下 tauri 仍会初始化 GTK 后端，容器内没有显示器会 panic
# （tao event_loop.rs:217 "Failed to initialize gtk backend!"），需要虚拟显示。
# xauth 必须一起装：xvfb-run 在缺少它时直接报 "xauth command not found"。
# 必须让 xvfb-run 作为 sh 的子进程（这里不能 exec）：xvfb-run 靠 SIGUSR1 判断
# Xvfb 就绪，而容器 PID 1 会屏蔽该信号，一旦 xvfb-run 占着 PID 1 就永久卡在 wait。
ENTRYPOINT ["/bin/sh", "-c", "xvfb-run -a /usr/local/bin/trilane-gui \"$@\"", "--"]
CMD ["--headless"]
