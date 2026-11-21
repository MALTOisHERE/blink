FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
# node:22-alpine already ships a "node" user/group at a fixed UID/GID 1000 -
# reuse it instead of creating our own, so the UID a host bind-mount's
# ownership needs to match is a documented, stable value instead of
# whatever "next available" an ad-hoc adduser happens to pick at build time.
USER node
EXPOSE 3001
ENV NODE_ENV=production PORT=3001
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://localhost:3001/api/stats || exit 1
CMD ["node", "server.js"]
