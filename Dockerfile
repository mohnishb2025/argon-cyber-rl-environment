FROM node:20-slim

WORKDIR /app

# Install dependencies for target repository (acme-checkout-service)
COPY acme-checkout-service/package*.json ./acme-checkout-service/
RUN cd acme-checkout-service && npm install

# Install dependencies for CRS Agent Backend (OODA + RL + Gemini 4 Argon)
COPY crs-agent-backend/package*.json ./crs-agent-backend/
RUN cd crs-agent-backend && npm install

# Copy full workspace source (including RL Q-table memory & Turbopack telemetry)
COPY acme-checkout-service ./acme-checkout-service
COPY crs-agent-backend ./crs-agent-backend

WORKDIR /app/crs-agent-backend

ENV PORT=8080
EXPOSE 8080

CMD ["node", "agent-server.js"]
