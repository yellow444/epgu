#!/bin/sh
# Все проверки репозитория одной командой.
#
# Раньше это гоняли GitHub Actions. Автоматики в репозитории больше нет:
# стенд закрытый, репозиторий один, и держать чужую инфраструктуру ради трёх
# команд незачем. Набор проверок при этом остался тот же самый.
#
# Запуск из корня репозитория:
#   sh scripts/check_all.sh
#
# Перед запуском установите backend requirements-test и frontend npm dependencies.
set -e

echo "== гигиена репозитория =="
python scripts/check_repository_hygiene.py

echo "== типографика =="
python scripts/check_text_style.py

echo "== бэкенд: тесты =="
(cd api-gosuslugi-backend && python -m pytest -q --no-header -p no:warnings)

echo "== библиотека python-epgu =="
if command -v ruff >/dev/null 2>&1; then
    (cd python-epgu && ruff check . && ruff format --check .)
else
    echo "ruff не установлен, пропускаю"
fi
if python -c "import pytest" >/dev/null 2>&1; then
    (cd python-epgu && python -m pytest -q)
else
    echo "pytest на хосте не установлен, пропускаю"
fi

echo "== клиент =="
(cd api-gosuslugi-client && CI=true npx --no-install react-scripts test --watchAll=false --runInBand)
(cd api-gosuslugi-client && CI=true npx --no-install react-scripts build >/dev/null)

echo "== всё прошло =="
