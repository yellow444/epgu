# personal/ — личные сертификаты

Эта папка предназначена для сертификатов пользователей/организаций (`.cer`, `.crt`, `.pfx`, `.p12`).

- **Не коммитить.** Всё содержимое игнорируется git (`.gitignore`).
- Все `*.cer` из этой папки автоматически устанавливаются в `uMy` при запуске `entrypoint test.sh`.
- Для production — монтируйте каталог с сертификатами как volume в `/certs/personal`.

Пример (`docker-compose.override.yml`):

```yaml
services:
  api:
    volumes:
      - ./api-gosuslugi-backend/certs/personal:/certs/personal
```
