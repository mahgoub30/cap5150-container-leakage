FROM alpine:3.20
RUN apk add --no-cache python3 sysbench fio iperf3
RUN adduser -D -u 1000 tenant && mkdir /data && chown tenant:tenant /data
COPY lab /lab
WORKDIR /lab
CMD ["sleep", "infinity"]
