#!/bin/sh
# Отправить копию репозитория в зеркало.
#
# Основной репозиторий - yellow444/epgu, зеркало - приватная копия в другом
# аккаунте. Авторство коммитов зеркало не меняет: в них остаётся тот же
# yellow444, меняется только то, куда они лежат.
#
# Разовая настройка, если зеркало в другом аккаунте GitHub. Каждый remote ходит
# под своим аккаунтом, поэтому зеркалу прописан собственный credential helper:
# он спрашивает токен у gh по имени аккаунта и ничего не хранит на диске.
#
#   git remote add mirror https://<аккаунт>@github.com/<аккаунт>/epgu.git
#   git config --local credential.https://github.com/<аккаунт>.useHttpPath true
#   git config --local credential.https://github.com/<аккаунт>.helper \
#     '!f() { test "$1" = get && { echo username=<аккаунт>; echo "password=$(gh auth token --user <аккаунт>)"; }; }; f'
#
# Активный аккаунт gh при этом не меняется: основной репозиторий продолжает
# ходить под своим. Переключать gh туда-сюда не нужно и опасно - легко забыть
# вернуть обратно.
#
# Дальше просто:
#   sh scripts/push_mirror.sh
set -e

REMOTE="${MIRROR_REMOTE:-mirror}"
BRANCHES="${MIRROR_BRANCHES:-main feat/python-epgu-library}"

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
