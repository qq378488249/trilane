# TriLane headless 镜像（runtime-only）
# 二进制在 WSL 宿主编译后 COPY 进来，镜像里不再跑 cargo/Node 构建；
# 前置步骤见 docker/WSL_BUILD_PLAN.md。
# 构建（在仓库根执行）：
#   docker build -f docker/linux-headless.Dockerfile -t trilane-headless .
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

# 与 WSL 构建环境（Ubuntu 24.04 / glibc 2.39 / webkit2gtk 2.52）同代，
# 避免二进制在旧版 bookworm 运行时里出现 GLIBC/WebKit 符号缺失。
FROM docker.1ms.run/library/ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

# 运行期没有外网，智能体需要的工具必须在构建期装好。
RUN sed -i 's|http://archive.ubuntu.com/ubuntu/|http://mirrors.huaweicloud.com/ubuntu/|g; s|http://security.ubuntu.com/ubuntu/|http://mirrors.huaweicloud.com/ubuntu/|g' \
      /etc/apt/sources.list.d/ubuntu.sources \
 && apt-get update && apt-get install -y --no-install-recommends \
      libwebkit2gtk-4.1-0 libgtk-3-0 libsoup-3.0-0 libjavascriptcoregtk-4.1-0 \
      libayatana-appindicator3-1 librsvg2-2 \
      ca-certificates bash \
      xvfb xauth \
      ripgrep python3 xxd file jq curl binutils bsdextrautils \
    && rm -rf /var/lib/apt/lists/*

# docker CLI：默认连每任务 DinD 的 socket（--isolation host 时才连宿主 daemon）
COPY --from=docker.1ms.run/library/docker:cli /usr/local/bin/docker /usr/local/bin/docker

COPY --chmod=755 docker/bin/trilane-gui /usr/local/bin/trilane-gui

# 运行时按固定路径读取 SOP；代码里的回退是 CARGO_MANIFEST_DIR，路径必须一致。
COPY trilane-rs/trilane-gui/sop/ /src/trilane-rs/trilane-gui/sop/

# headless 模式下 tauri 仍会初始化 GTK 后端，容器内没有显示器会 panic，
# 需要虚拟显示。xauth 必须一起装：xvfb-run 缺少它时会直接报命令不存在。
# 必须让 xvfb-run 作为 sh 的子进程（这里不能 exec）：xvfb-run 靠 SIGUSR1 判断
# Xvfb 就绪，而容器 PID 1 会屏蔽该信号，一旦 xvfb-run 占着 PID 1 就永久卡在 wait。
ENTRYPOINT ["/bin/sh", "-c", "xvfb-run -a /usr/local/bin/trilane-gui \"$@\"", "--"]
CMD ["--headless"]
