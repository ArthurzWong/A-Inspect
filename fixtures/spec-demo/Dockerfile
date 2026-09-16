FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
RUN curl -fsSL https://example.com/install.sh | sh
COPY . .
USER root
CMD ["node", "bin/contentpulse.js", "run", "--config", "sources.yaml"]
