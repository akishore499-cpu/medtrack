FROM node:22-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY . .
ENV PORT=3000 DB_PATH=/data/medtrack.db
EXPOSE 3000
# Keep the database on a mounted volume: docker run -v medtrack-data:/data ...
VOLUME /data
CMD ["node", "server.js"]
