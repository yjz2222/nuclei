FROM golang:1.17.6-alpine as builder
COPY . /app
RUN go env -w GOPROXY=http://10.10.30.7/repository/goproxy/,direct \
    && cd /app/v2 && go mod tidy \
    && go build -o mypoc /app/v2/cmd/nuclei-server/main.go

FROM alpine:3.15.0
COPY --from=builder /app/v2/mypoc /usr/local/bin/mypoc
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories \
    && apk add -U tzdata && ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
CMD sleep 30 && mypoc