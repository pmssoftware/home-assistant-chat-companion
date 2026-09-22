FROM ghcr.io/home-assistant/base:latest

ARG BUILD_VERSION=dev
ARG BUILD_ARCH

LABEL \
    io.hass.name="Home Assistant Chat Companion" \
    io.hass.description="Federation and native-client backend for Home Assistant Chat" \
    io.hass.version="${BUILD_VERSION}" \
    io.hass.type="app" \
    io.hass.arch="${BUILD_ARCH}"

RUN apk add --no-cache openssl python3

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/home-assistant-chat/src

WORKDIR /opt/home-assistant-chat
COPY src ./src
COPY run.sh /run.sh
RUN chmod 0755 /run.sh

CMD ["/run.sh"]
