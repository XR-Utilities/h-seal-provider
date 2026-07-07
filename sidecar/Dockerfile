# Self-contained: the SDK comes from the public git dep in package.json, so this
# builds from the sidecar/ directory alone (no parent context needed).
# Build:  docker build -t hseal-sidecar sidecar/
# Run:    docker run -p 8791:8791 --env-file sidecar/.env hseal-sidecar
FROM node:22-slim AS build
WORKDIR /app
# git is needed to resolve the github: dependency.
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY tsconfig.json server.ts ./
RUN npm run build

FROM node:22-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
ENV NODE_ENV=production PORT=8791
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY --from=build /app/dist ./dist
EXPOSE 8791
CMD ["node", "dist/server.js"]
