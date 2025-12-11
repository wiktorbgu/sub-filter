# Build stage
FROM golang:alpine AS builder

# Установка зависимостей (для статической сборки с CGO=0)
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Копируем исходники
COPY . .

# Собираем статический бинарник (без CGO, с поддержкой часовых поясов)
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags '-w -s -extldflags "-static"' \
    -tags timetzdata \
    -o filter main.go

# Final stage
FROM scratch

# Копируем SSL-сертификаты для HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Копируем бинарник
COPY --from=builder /app/filter /filter

EXPOSE 8000

# Точка входа — позволяет передавать аргументы при запуске
ENTRYPOINT ["/filter"]