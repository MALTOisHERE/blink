# Pinned by digest (the multi-arch index, not a single-platform manifest -
# so this still resolves correctly regardless of build/host architecture),
# not just the "22-alpine" tag, so a build can't silently pick up a
# different image than the one actually reviewed/tested. Re-resolve with
# `docker buildx imagetools inspect node:22-alpine` when bumping Node
# versions or picking up a security patch in the base image.
FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a
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
