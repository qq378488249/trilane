# TriLane headless image (task-execution runtime)
# The TriLane binary is compiled on the WSL host and copied into this image.
# No Cargo/Node build is performed inside the image.
#
# Build from the repository root:
#   docker build -f docker/linux-headless.Dockerfile -t trilane-headless .
#
# Run example:
#   docker run --rm \
#     -v /var/run/docker.sock:/var/run/docker.sock \
#     -v <task_dir>:/task \
#     -v <out_dir>:/out \
#     -v <home_dir>:/root/.trilane \
#     trilane-headless \
#     --objective-file /task/TASK.md \
#     --out-dir /out \
#     --cwd /task/workspace \
#     --audit-mode lab \
#     --headless-timeout-sec 3600
#
# This is intentionally a lean runtime image. It contains the tools directly
# justified by the current workflow: source/file inspection, task submission,
# binary inspection, and local GDB tracing. Compiler/fuzzer toolchains are not
# installed until the agent actually needs to build or instrument a target.

# syntax=docker/dockerfile:1.7

FROM docker.1ms.run/library/ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# GUI runtime + minimal task-analysis utilities.
RUN set -eux; \
    sed -i \
      -e 's#http://archive.ubuntu.com/ubuntu#http://mirrors.huaweicloud.com/ubuntu#g' \
      -e 's#http://security.ubuntu.com/ubuntu#http://mirrors.huaweicloud.com/ubuntu#g' \
      /etc/apt/sources.list.d/ubuntu.sources; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      bash \
      xvfb \
      xauth \
      libwebkit2gtk-4.1-0 \
      libgtk-3-0 \
      libsoup-3.0-0 \
      libjavascriptcoregtk-4.1-0 \
      libayatana-appindicator3-1 \
      librsvg2-2 \
      \
      ripgrep \
      python3 \
      unzip \
      tar \
      gzip \
      file \
      xxd \
      jq \
      curl \
      binutils \
      bsdextrautils \
      afl++ \
      gdb; \
    rm -rf /var/lib/apt/lists/*

# Docker CLI: connects to the per-task DinD socket mounted at runtime.
COPY --from=docker.1ms.run/library/docker:cli \
    /usr/local/bin/docker /usr/local/bin/docker

# Prebuilt TriLane application binary; build it on WSL before docker build.
COPY --chmod=755 docker/bin/trilane-gui \
    /usr/local/bin/trilane-gui

# Runtime SOP path used by the application. Keep this path in sync with the
# application's configured fallback path (CARGO_MANIFEST_DIR in source builds).
COPY trilane-rs/trilane-gui/sop/ \
    /src/trilane-rs/trilane-gui/sop/

# Verify only the tools installed in this lean image.
RUN set -eux; \
    command -v docker; \
    command -v rg; \
    command -v python3; \
    command -v tar; \
    command -v gzip; \
    command -v file; \
    command -v xxd; \
    command -v jq; \
    command -v curl; \
    command -v objdump; \
    command -v readelf; \
    command -v addr2line; \
    command -v gdb; \
    command -v xvfb-run; \
    command -v unzip; \
    docker --version; \
    command -v afl-fuzz; \
    gdb --version >/dev/null

# Headless Tauri still initializes GTK. xvfb-run must remain a child of /bin/sh:
# xvfb-run waits for Xvfb readiness using SIGUSR1, and making it PID 1 can cause
# that readiness wait to hang in some container runtimes.
ENTRYPOINT ["/bin/sh", "-c", "xvfb-run -a /usr/local/bin/trilane-gui \"$@\"", "--"]
CMD ["--headless"]
