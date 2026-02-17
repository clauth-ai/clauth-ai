# Stage 1: Build
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci
COPY src/ src/
RUN npm run build

# Stage 2: Runtime
FROM node:22-alpine
RUN addgroup -S clauth && adduser -S clauth -G clauth
WORKDIR /app
COPY --from=build /app/dist dist/
COPY --from=build /app/package.json .
USER clauth
EXPOSE 4317
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:4317/health || exit 1
ENTRYPOINT ["node", "dist/daemon/server.js"]
