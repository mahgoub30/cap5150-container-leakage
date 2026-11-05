# Image used for both the victim and the attacker container.
# It only adds the standard tools the tests need; no security settings are
# changed here, so a plain "docker run" of this image is the Tier 1 default.
FROM alpine:3.20
RUN apk add --no-cache python3 sysbench fio iperf3
# Unprivileged user for the hardened tiers. /data is where the victim's disk
# workload writes (a Docker-managed volume, not a host mount).
RUN adduser -D -u 1000 tenant && mkdir /data && chown tenant:tenant /data
COPY lab /lab
WORKDIR /lab
CMD ["sleep", "infinity"]
