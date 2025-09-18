FROM golang:1.23-alpine AS builder


WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY *.go ./

RUN CGOOS=linux go build -ldflags="-s -w" -o /server

FROM alpine:latest

COPY --from=builder /server /server

EXPOSE 8080

CMD ["/server"]