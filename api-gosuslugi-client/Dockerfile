FROM node:18-alpine AS build
WORKDIR /app
ARG BACKEND_URL=/api
ENV REACT_APP_BACKEND_URL=${BACKEND_URL}
COPY package*.json .npmrc ./
RUN npm config set registry https://registry.npmjs.org/ && \
    npm config set fetch-retries 15 && \
    npm config set fetch-retry-maxtimeout 180000 && \
    npm config set fetch-retry-mintimeout 15000 && \
    npm config set fetch-retry-factor 10 && \
    npm config set fetch-timeout 300000 && \
    npm install --prefer-offline --no-audit --no-fund
COPY . . 
RUN npm run build
FROM nginx:stable-alpine 
COPY --from=build /app/build /usr/share/nginx/html 
COPY --from=build /app/default.conf /etc/nginx/conf.d/default.conf
#RUN rm -f /etc/nginx/conf.d/default.conf
EXPOSE 80
