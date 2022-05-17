FROM golang:1.17.6-alpine as builder
COPY . /app
RUN go env -w GOPROXY=https://goproxy.cn,direct \
    && cd /app/v2 && go mod tidy \
    && go build -o mypoc /app/v2/cmd/nuclei-server/main.go

FROM alpine:3.15.0
COPY --from=builder /app/v2/mypoc /usr/local/bin/mypoc
CMD sleep 30 && mypoc