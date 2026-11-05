# same image for the victim and the attacker
FROM alpine:3.20
RUN apk add --no-cache python3 sysbench fio iperf3
# non-root user for tiers 2 and 3; /data is the victim's volume
RUN adduser -D -u 1000 tenant && mkdir /data && chown tenant:tenant /data
COPY lab /lab
WORKDIR /lab
CMD ["sleep", "infinity"]
