FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends docker.io python3 make g++ && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json .
RUN npm install --omit=dev
COPY terminal-server.js .
CMD ["node", "terminal-server.js"]
