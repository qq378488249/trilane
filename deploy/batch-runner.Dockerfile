# 跑批编排器镜像：只负责跑 cybergym_batch.py，不包含智能体本体
#
# 分工：
#   本镜像（trilane-batch-runner）= python + requests + docker CLI + cybergym_batch.py
#     └─ 通过挂载的 docker.sock 调宿主 daemon
#          ├─ trilane-dind-<task>（每任务一个，默认隔离）
#          │    └─ 智能体在 dind 里起 n132/arvo:<id>-vul 跑 PoC
#          └─ trilane-headless 容器（每个任务一个）
#
# 构建（在 deploy/ 目录执行；构建上下文只有本目录，镜像很小）：
#   cd deploy
#   docker build -f batch-runner.Dockerfile -t trilane-batch-runner:latest .
#
# 关键点：本容器里发出的 `docker run -v X:Y` 由宿主 daemon 解析，路径必须按**宿主**
# 文件系统写。所以运行本镜像时所有目录都用同路径挂载（-v /opt/x:/opt/x），
# 脚本里的 daemon_path() 在 Linux 上原样返回路径，不需要 Windows 那套 /host_mnt 换算。

FROM docker.1ms.run/library/python:3.12-slim

# apt 走国内镜像；服务器能直连 Debian 官方源时把这两行换成默认源即可
RUN sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' \
      /etc/apt/sources.list.d/debian.sources 2>/dev/null || true

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl tzdata \
 && rm -rf /var/lib/apt/lists/*

# 只装跑批脚本需要的依赖，不引入任何智能体运行时的东西
RUN pip install --no-cache-dir requests

# docker CLI：脚本靠它 docker run / docker images / docker pull。
# 只装客户端，daemon 是宿主的（通过 /var/run/docker.sock 接入）。
COPY --from=docker.1ms.run/library/docker:cli /usr/local/bin/docker /usr/local/bin/docker

WORKDIR /opt/trilane-batch
COPY cybergym_batch.py /opt/trilane-batch/cybergym_batch.py

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Shanghai \
    # 容器里这两个默认值必须指向宿主路径（同路径挂载后两边一致）
    CYBERGYM_DATA_DIR=/opt/cybergym_data \
    CYBERGYM_SERVER=http://127.0.0.1:8666

ENTRYPOINT ["python3", "/opt/trilane-batch/cybergym_batch.py"]
CMD ["--help"]
