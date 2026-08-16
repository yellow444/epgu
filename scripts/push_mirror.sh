#!/bin/sh
# Отправить копию репозитория в зеркало.
#
# Основной репозиторий - yellow444/epgu, зеркало - приватная копия в другом
# аккаунте. Авторство коммитов зеркало не меняет: в них остаётся тот же
# yellow444, меняется только то, куда они лежат.
#
# Разовая настройка, если зеркало в другом аккаунте GitHub. Аккаунт задаётся
# именем пользователя прямо в адресе: оно попадает в запрос учётных данных, и
# хранилище отдаёт строку именно этого аккаунта. Без имени git берёт первую
# подходящую запись по хосту, а их на машине несколько.
#
#   git remote add mirror https://<аккаунт>@github.com/<аккаунт>/epgu.git
#   git config --local credential.https://github.com/<аккаунт>.helper ""
#   git config --local --add credential.https://github.com/<аккаунт>.helper store
#   git config --local credential.https://github.com/<аккаунт>.useHttpPath false
#
# Пустое значение helper сбрасывает всё, что настроено выше по цепочке, дальше
# остаётся только store. useHttpPath именно false: записи в ~/.git-credentials
# лежат без пути, и при true git их не находит.
#
# Проверить, что аккаунты не перепутаны:
#   git ls-remote origin && git ls-remote mirror
#
# Дальше просто:
#   sh scripts/push_mirror.sh
set -e

REMOTE="${MIRROR_REMOTE:-mirror}"
BRANCHES="${MIRROR_BRANCHES:-main feat/python-epgu-library}"

if ! git remote get-url "$REMOTE" >/dev/null 2>&1; then
    echo "Зеркало не настроено. Добавьте remote:" >&2
    echo "  git remote add $REMOTE https://<аккаунт>@github.com/<аккаунт>/epgu.git" >&2
    exit 1
fi

MIRROR_URL=$(git remote get-url "$REMOTE")
ORIGIN_URL=$(git remote get-url origin 2>/dev/null || echo "")

# Имя пользователя в адресе - единственное, что различает аккаунты при выборе
# учётных данных. Без него push уйдёт под первый попавшийся и упрётся в 403.
for url in "$MIRROR_URL" "$ORIGIN_URL"; do
    [ -n "$url" ] || continue
    case "$url" in
        *@github.com/*) ;;
        https://github.com/*)
            echo "В адресе нет имени аккаунта: $url" >&2
            echo "Аккаунт выберется случайно. Поправьте так:" >&2
            echo "  git remote set-url <remote> https://<аккаунт>@github.com/<путь>" >&2
            exit 1
            ;;
    esac
done

MIRROR_ACCOUNT=$(printf '%s' "$MIRROR_URL" | sed -n 's#^https://\([^@]*\)@.*#\1#p')
ORIGIN_ACCOUNT=$(printf '%s' "$ORIGIN_URL" | sed -n 's#^https://\([^@]*\)@.*#\1#p')
if [ -n "$ORIGIN_ACCOUNT" ] && [ "$MIRROR_ACCOUNT" = "$ORIGIN_ACCOUNT" ]; then
    echo "Зеркало и основной репозиторий указаны под одним аккаунтом: $MIRROR_ACCOUNT" >&2
    echo "Проверьте адреса, копия должна уходить под своим владельцем." >&2
    exit 1
fi

echo "Зеркало: $MIRROR_URL (аккаунт $MIRROR_ACCOUNT)"
echo "Основной: ${ORIGIN_URL:-не настроен} (аккаунт ${ORIGIN_ACCOUNT:-неизвестен})"

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
