FROM debian:bookworm-slim

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        lynis \
        python3 \
        python3-pip \
        python3-venv \
        cron \
        procps \
        && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /venv
RUN /venv/bin/pip install --no-cache-dir mcp

WORKDIR /app
COPY mcp_server.py .
COPY entrypoint.sh .
COPY custom.prf /etc/lynis/custom.prf
RUN chmod +x entrypoint.sh

ENV REPORTS_DIR=/lynis-reports
ENV MCP_MODE=0
ENV CRON_SCHEDULE="0 2 * * *"

ENTRYPOINT ["/app/entrypoint.sh"]
