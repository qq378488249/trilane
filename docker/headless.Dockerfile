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

# ---------- builder ----------
FROM docker.1ms.run/library/rust:1.95-bookworm AS builder
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

WORKDIR /src
COPY trilane-rs/ trilane-rs/
# 前端 dist 在宿主上构建（平台无关），镜像内不需要 Node
COPY trilane-rs/trilane-gui/frontend/dist/ trilane-rs/trilane-gui/frontend/dist/
# 预置 rusty_v8 静态库，避免构建时访问 GitHub
COPY docker/rusty_v8/ /usr/local/cargo/.rusty_v8/

ENV CARGO_BUILD_JOBS=2
WORKDIR /src/trilane-rs
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/trilane-rs/target \
    cargo build -p trilane-gui --release \
 && cp target/release/trilane-gui /usr/local/bin/trilane-gui

# ---------- runtime ----------
FROM docker.1ms.run/library/debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources \
 && apt-get update && apt-get install -y --no-install-recommends \
      libwebkit2gtk-4.1-0 libgtk-3-0 libsoup-3.0-0 libjavascriptcoregtk-4.1-0 \
      ca-certificates bash \
      xvfb xauth \
    && rm -rf /var/lib/apt/lists/*

# docker CLI：默认连每任务 DinD 的 socket（--isolation host 时才连宿主 daemon）
COPY --from=docker.1ms.run/library/docker:cli /usr/local/bin/docker /usr/local/bin/docker

COPY --from=builder /usr/local/bin/trilane-gui /usr/local/bin/trilane-gui
# headless 模式下 tauri 仍会初始化 GTK 后端，容器内没有显示器会 panic
# （tao event_loop.rs:217 "Failed to initialize gtk backend!"），需要虚拟显示。
# xauth 必须一起装：xvfb-run 在缺少它时直接报 "xauth command not found"。
# 必须让 xvfb-run 作为 sh 的子进程（这里不能 exec）：xvfb-run 靠 SIGUSR1 判断
# Xvfb 就绪，而容器 PID 1 会屏蔽该信号，一旦 xvfb-run 占着 PID 1 就永久卡在 wait。
ENTRYPOINT ["/bin/sh", "-c", "xvfb-run -a /usr/local/bin/trilane-gui \"$@\"", "--"]
CMD ["--headless"]
