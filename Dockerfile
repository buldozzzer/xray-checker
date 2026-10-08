FROM python:3.11-slim

ARG XRAY_VERSION=v26.3.27
ARG TARGETARCH=amd64

RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates iputils-ping \
    && case "$TARGETARCH" in \
         amd64) XARCH=64 ;; \
         arm64) XARCH=arm64-v8a ;; \
         *) echo "unsupported arch $TARGETARCH" && exit 1 ;; \
       esac \
    && curl -fsSL -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${XARCH}.zip" \
    && unzip /tmp/xray.zip xray -d /usr/local/bin \
    && chmod +x /usr/local/bin/xray \
    && rm /tmp/xray.zip \
    && apt-get purge -y unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY checker.py app.py history.py ./
COPY static ./static

ENV XRAY_BIN=/usr/local/bin/xray \
    PORT=8080 \
    PYTHONUNBUFFERED=1

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
    CMD curl -fs http://127.0.0.1:8080/api/state -o /dev/null || exit 1
CMD ["python", "app.py"]
