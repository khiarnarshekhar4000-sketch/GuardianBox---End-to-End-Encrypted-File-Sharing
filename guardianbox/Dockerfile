FROM node:22-slim AS build
WORKDIR /app
COPY package.json ./
COPY backend/package.json backend/
COPY frontend/package.json frontend/
RUN npm install
COPY . .
RUN npm run build

FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production PORT=3001
COPY --from=build /app /app
RUN npm prune --omit=dev && mkdir -p /app/data && chown -R node:node /app/data
USER node
EXPOSE 3001
CMD ["node", "backend/src/server.js"]
