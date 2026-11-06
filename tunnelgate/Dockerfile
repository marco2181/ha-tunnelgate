ARG BUILD_FROM
FROM $BUILD_FROM

# main.py receives SIGTERM first and has time to remove its network rules
ENV S6_CMD_RECEIVE_SIGNALS=1 \
    S6_KILL_GRACETIME=15000

RUN apk add --no-cache \
      python3 \
      py3-paho-mqtt \
      wireguard-tools-wg \
      wireguard-go \
      iptables \
      iproute2 \
      conntrack-tools

COPY app /app

CMD ["python3", "-u", "/app/main.py"]
