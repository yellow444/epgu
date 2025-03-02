FROM node:18-alpine AS build
WORKDIR /app
ARG BACKEND_URL=http://192.168.50.100/api
ENV REACT_APP_BACKEND_URL=${BACKEND_URL}
COPY package*.json ./
RUN npm install
COPY . . 
RUN npm run build 
FROM nginx:stable-alpine 
COPY --from=build /app/build /usr/share/nginx/html 
COPY --from=build /app/default.conf /etc/nginx/conf.d/default.conf
#RUN rm -f /etc/nginx/conf.d/default.conf
EXPOSE 80
