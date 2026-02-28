docker-compose down
docker-compose --env-file .env -f .\docker-compose.yml up -d --build
#--build --force-recreate