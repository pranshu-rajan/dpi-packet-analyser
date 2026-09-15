FROM python:3.11-slim-bookworm

# Install C++ compiler and build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy C++ DPI engine source and build binary
COPY Packet_analyzer/ /app/Packet_analyzer/
WORKDIR /app/Packet_analyzer
RUN g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp && \
    chmod +x dpi_engine

# Setup Python backend
WORKDIR /app/backend
COPY backend/requirements.txt /app/backend/
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ /app/backend/

# Ensure runtime directories exist
RUN mkdir -p /app/backend/uploads /app/backend/outputs

ENV DPI_ENGINE_PATH=/app/Packet_analyzer/dpi_engine
ENV PORT=8000
ENV HOST=0.0.0.0

EXPOSE 8000

CMD ["sh", "-c", "python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
