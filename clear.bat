docker-compose down
docker-compose --env-file .env -f .\docker-compose.yml up -d
@REM --build --force-recreate