FROM node:24-alpine AS build
WORKDIR /app
ARG BACKEND_URL=/api
ENV REACT_APP_BACKEND_URL=${BACKEND_URL}
COPY package*.json .npmrc ./
RUN npm ci --prefer-offline --no-audit --no-fund
COPY . . 
RUN npm run build
FROM nginx:stable-alpine 
COPY --from=build /app/build /usr/share/nginx/html 
COPY --from=build /app/default.conf /etc/nginx/conf.d/default.conf
COPY --from=build --chmod=755 /app/entrypoint.sh /entrypoint.sh
COPY --from=build /app/default.conf.template /etc/nginx/conf.d/default.conf.template
ENV BACKEND_API=http://api:5000
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1/ >/dev/null || exit 1
ENTRYPOINT ["/entrypoint.sh"]
