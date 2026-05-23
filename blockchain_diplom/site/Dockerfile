FROM golang:1.24-alpine AS builder
WORKDIR /build
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/*.go ./
RUN CGO_ENABLED=0 go build -o verifier-server .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /build/verifier-server .
COPY frontend/ ./frontend/
EXPOSE 8080
CMD ["./verifier-server"]
