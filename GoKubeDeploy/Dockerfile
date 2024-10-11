# Dockerfile
FROM golang:1.16-alpine AS builder

WORKDIR /app

COPY . /app  

RUN go build -o /healthcheck github.com/elliotsecops/GoKubeDeploy/src

FROM alpine:latest

WORKDIR /root/

COPY --from=builder /healthcheck /root/ 

CMD ["./healthcheck"]