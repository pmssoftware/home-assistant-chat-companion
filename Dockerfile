FROM python:3.12-slim

LABEL org.opencontainers.image.title="Home Assistant Chat Companion"
LABEL org.opencontainers.image.description="Federation and standalone-client backend for Home Assistant Chat"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/hachat/src

WORKDIR /opt/hachat
COPY home_assistant_chat_companion/src ./src

RUN groupadd --system --gid 10001 hachat \
    && useradd --system --uid 10001 --gid hachat --home-dir /nonexistent --shell /usr/sbin/nologin hachat \
    && mkdir /data \
    && chown hachat:hachat /data

USER 10001:10001
VOLUME ["/data"]
EXPOSE 8210 8211

ENTRYPOINT ["python3", "-m", "hachat_companion", "--database", "/data/companion.sqlite3"]
CMD ["serve", "--client-listen", "0.0.0.0:8210", "--federation-listen", "0.0.0.0:8211", "--allow-insecure-client-http", "--allow-insecure-federation-http"]
