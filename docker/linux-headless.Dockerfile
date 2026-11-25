# TriLane headless image (task-execution runtime)
# Binary is compiled on WSL host. No Cargo/Node build here.
#
# Build:
# docker build -f docker/linux-headless.Dockerfile -t trilane-headless .
#
# Run:
# docker run --rm \
#   -v /var/run/docker.sock:/var/run/docker.sock \
#   -v <task_dir>:/task \
#   -v <out_dir>:/out \
#   -v <home_dir>:/root/.trilane \
#   trilane-headless \
#   --objective-file /task/TASK.md \
#   --out-dir /out \
#   --cwd /task/workspace \
#   --audit-mode lab \
#   --headless-timeout-sec 3600

# syntax=docker/dockerfile:1.7

FROM docker.1ms.run/library/ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    LLVM_VERSION=18 \
    PATH="/usr/lib/llvm-18/bin:${PATH}" \
    ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer-18

# Runtime libraries and CyberGym analysis toolchain
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
      git \
      ripgrep \
      python3 \
      python3-dev \
      python3-pip \
      python3-venv \
      python3-yaml \
      python3-requests \
      \
      file \
      xxd \
      jq \
      curl \
      wget \
      unzip \
      xz-utils \
      zstd \
      sqlite3 \
      tree \
      less \
      procps \
      psmisc \
      bsdextrautils \
      binutils \
      strace \
      ltrace \
      \
      build-essential \
      cmake \
      ninja-build \
      pkg-config \
      \
      gdb \
      gdbserver \
      \
      clang-18 \
      clang-tools-18 \
      llvm-18 \
      llvm-18-tools \
      llvm-18-dev \
      lld-18 \
      libclang-18-dev \
      libclang-rt-18-dev \
      libfuzzer-18-dev \
      \
      afl++; \
    rm -rf /var/lib/apt/lists/*

# Docker CLI
COPY --from=docker.1ms.run/library/docker:cli \
    /usr/local/bin/docker /usr/local/bin/docker

# Prebuilt TriLane binary
COPY --chmod=755 docker/bin/trilane-gui \
    /usr/local/bin/trilane-gui

# SOP files
COPY trilane-rs/trilane-gui/sop/ \
    /src/trilane-rs/trilane-gui/sop/

# Verify tools and libFuzzer + sanitizer runtime
RUN set -eux; \
    command -v docker; \
    command -v rg; \
    command -v gdb; \
    command -v strace; \
    command -v clang-18; \
    command -v clang++-18; \
    command -v llvm-config-18; \
    command -v llvm-link-18; \
    command -v llvm-symbolizer-18; \
    command -v afl-fuzz; \
    command -v afl-clang-fast; \
    docker --version; \
    clang-18 --version; \
    llvm-config-18 --version; \
    gdb --version >/dev/null; \
    afl-fuzz -V; \
    printf '%s\n' \
      '#include <stddef.h>' \
      '#include <stdint.h>' \
      'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {' \
      '  (void)data; (void)size; return 0;' \
      '}' > /tmp/trilane-libfuzzer-smoke.c; \
    clang-18 -g -O1 -fsanitize=fuzzer,address,undefined \
      /tmp/trilane-libfuzzer-smoke.c \
      -o /tmp/trilane-libfuzzer-smoke; \
    /tmp/trilane-libfuzzer-smoke -runs=10 \
      >/tmp/trilane-libfuzzer-smoke.log 2>&1; \
    tail -n 5 /tmp/trilane-libfuzzer-smoke.log; \
    rm -f /tmp/trilane-libfuzzer-smoke.c \
      /tmp/trilane-libfuzzer-smoke \
      /tmp/trilane-libfuzzer-smoke.log

# Xvfb must run as a child of sh, not PID 1.
ENTRYPOINT ["/bin/sh", "-c", "xvfb-run -a /usr/local/bin/trilane-gui \"$@\"", "--"]
CMD ["--headless"]