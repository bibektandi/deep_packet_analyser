# Stage 1: Build the C++ DPI Engine
FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Compile multi-threaded C++ DPI Engine for Linux
RUN g++ -std=c++17 -pthread -O2 -I include \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp \
    -o dpi_engine

# Stage 2: Lightweight Runtime Container
FROM python:3.11-slim

WORKDIR /app

# Copy compiled C++ binary and web application files
COPY --from=builder /app/dpi_engine /app/dpi_engine
COPY --from=builder /app/test_dpi.pcap /app/test_dpi.pcap
COPY server.py /app/server.py
COPY frontend/ /app/frontend/

# Expose web server port
EXPOSE 8080

# Run Web Dashboard Server
CMD ["python", "server.py"]
