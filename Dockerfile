# Etapa de construcción
FROM golang:1.25.6-bullseye AS builder
WORKDIR /app

COPY go.mod go.sum ./

# Descargar dependencias
RUN go mod download

# Copiar el resto del código
COPY . .

# Compilar el binario estático para Linux
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o go-api .

# Etapa de ejecución
FROM debian:bullseye-slim
WORKDIR /app

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/go-api .

ENV PORT=8080
EXPOSE 8080

CMD ["./go-api"]