#!/bin/sh
# Отправить копию репозитория в зеркало.
#
# Основной репозиторий - yellow444/epgu, зеркало - приватная копия в другом
# аккаунте. Авторство коммитов зеркало не меняет: в них остаётся тот же
# yellow444, меняется только то, куда они лежат.
#
# Разовая настройка:
#   1. Владелец зеркала создаёт приватный репозиторий и даёт yellow444 право
#      записи (Settings, Collaborators). Тогда push пойдёт уже настроенными
#      учётными данными, второй аккаунт в системе заводить не нужно.
#   2. git remote add mirror https://github.com/<аккаунт>/epgu.git
#
# Дальше просто:
#   sh scripts/push_mirror.sh
set -e

REMOTE="${MIRROR_REMOTE:-mirror}"
BRANCHES="${MIRROR_BRANCHES:-main}"

if ! git remote get-url "$REMOTE" >/dev/null 2>&1; then
    echo "Зеркало не настроено. Добавьте remote:" >&2
    echo "  git remote add $REMOTE https://github.com/<аккаунт>/epgu.git" >&2
    exit 1
fi

echo "Зеркало: $(git remote get-url "$REMOTE")"

for branch in $BRANCHES; do
    if git rev-parse --verify --quiet "$branch" >/dev/null; then
        echo "Отправляю ветку $branch"
        git push "$REMOTE" "$branch"
    else
        echo "Ветки $branch нет локально, пропускаю"
    fi
done

# Теги нужны для воспроизводимости релизов, но их отсутствие не ошибка.
if [ -n "$(git tag)" ]; then
    echo "Отправляю теги"
    git push "$REMOTE" --tags
fi

echo "Готово. Авторство коммитов не менялось: $(git log -1 --format='%an <%ae>')"
