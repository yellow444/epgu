/**
 * Сценарий подключения к ЕПГУ, разложенный на действия.
 *
 * Каждый шаг несёт то, что можно нажать: ссылку, письмо или сниппет.
 * `envKey` - ключ из ответа GET /environments, чтобы адрес брался с живого
 * backend, а не из захардкоженной константы. `url` - запасной вариант.
 */

export const TEST_COOKIES_SNIPPET = `document.cookie="access_poweratt=1; path=/; domain=.gosuslugi.ru; secure";
document.cookie="new-partners=1; path=/; domain=.gosuslugi.ru; secure";`;

export const CURL_TOKEN_SNIPPET = `# Тот же запрос, что делает кнопка «Проверить ключ».
# Ничего не уходит мимо: подпись формирует ваш backend, ответ приходит от ЕСИА.
curl -sS -X POST http://localhost:55000/accessTkn_esia \\
  -H 'Content-Type: application/json' \\
  -d '{"api_key":"<GUID-API-KEY>"}'`;

export const CURL_ESIA_SNIPPET = `# Прямой запрос в ЕСИА, минуя наш backend.
# signature - CAdES-BES подпись строки api_key вашим сертификатом.
curl -sS 'https://esia-portal1.test.gosuslugi.ru/esia-rs/api/public/v1/orgs/ext-app/<GUID-API-KEY>/tkn?signature=<signature>'`;

export const TEST_STEPS = [
  {
    id: 't1',
    title: 'Зарегистрировать ФЛ и организацию в тестовой ЕСИА',
    text: 'Сначала физлицо, затем от его имени - юрлицо. Тестовый контур живёт отдельно от боевого, боевая учётка здесь не подойдёт.',
    url: 'https://esia-portal1.test.gosuslugi.ru/registration/',
    linkLabel: 'Регистрация в тестовой ЕСИА',
    extraLinks: [
      { url: 'https://esia-portal1.test.gosuslugi.ru/logs/postcodes/', label: 'Коды подтверждения' },
    ],
  },
  {
    id: 't2',
    title: 'Запросить тестовый сертификат',
    text: 'Сертификат выпускает Оператор по письму. Установите его в лицензированный signing runtime с КриптоПро/PyCades и подключите внешнее хранилище ключей по документации поставщика.',
    letter: 'testCert',
  },
  {
    id: 't3',
    title: 'Включить сотрудника в нужные группы',
    text: 'В профиле организации: «Технологический портал» и «Администраторы профиля организации». Без них разделы техпортала не откроются.',
    envKey: 'esia_host',
    url: 'https://esia-portal1.test.gosuslugi.ru',
    linkLabel: 'Профиль организации в ЕСИА',
  },
  {
    id: 't4',
    title: 'Зарегистрировать ИС в технологическом портале ЕСИА',
    text: 'Понадобятся мнемоника, URL системы, описание и сертификат ИС. Мнемоника дальше фигурирует во всех письмах.',
    envKey: 'esia_tech_portal',
    url: 'https://esia-portal1.test.gosuslugi.ru/console/tech',
    linkLabel: 'Технологический портал, тест',
  },
  {
    id: 't5',
    title: 'Скачать API-Key в ЛК ИЭП',
    text: 'Раздел «Мои системы»: добавьте сотрудника и выгрузите ключ в CSV. Если разделы не видны - выполните сниппет в консоли браузера на домене gosuslugi.ru и обновите страницу.',
    url: 'https://svcdev-partners.test.gosuslugi.ru/systems',
    linkLabel: 'ЛК ИЭП / Мои системы, тест',
    code: TEST_COOKIES_SNIPPET,
    codeLabel: 'Cookies для тестового ЛК ИЭП',
  },
  {
    id: 't6',
    title: 'Заявка на настройку параметров ИС на ЕПГУ',
    text: 'Для каждой услуги Оператор прописывает параметры на своей стороне. Без этого push вернёт отказ даже с валидным ключом.',
    letter: 'epguParams',
  },
];

export const PROD_STEPS = [
  {
    id: 'p1',
    title: 'Подтверждённая УЗ руководителя и карточка ЮЛ',
    text: 'В промышленной ЕСИА. Карточка юрлица должна быть заполнена полностью, иначе техпортал не даст зарегистрировать ИС.',
    envKey: 'esia_host',
    url: 'https://esia.gosuslugi.ru',
    linkLabel: 'ЕСИА, промышленный контур',
  },
  {
    id: 'p2',
    title: 'Зарегистрировать промышленную ИС и загрузить боевой сертификат',
    text: 'Отдельная регистрация: тестовая ИС в проде не действует.',
    envKey: 'esia_tech_portal',
    url: 'https://esia.gosuslugi.ru/console/tech/',
    linkLabel: 'Технологический портал, прод',
  },
  {
    id: 'p3',
    title: 'Пройти совместное тестирование',
    text: 'По каждой подключаемой услуге отдельно. Протокол понадобится при подаче заявки на подключение.',
    letter: 'jointTesting',
  },
  {
    id: 'p4',
    title: 'Направить заявку на подключение к продуктивной среде',
    text: 'Официальное обращение с приложением протокола тестирования.',
    letter: 'prodAccess',
  },
  {
    id: 'p5',
    title: 'Получить боевой API-Key',
    text: 'В партнёрском личном кабинете. Полномочие на формирование ключа создаётся отдельным письмом, если его ещё нет.',
    url: 'https://partners.gosuslugi.ru',
    linkLabel: 'Партнёрский личный кабинет',
    letter: 'apiKeyPowers',
    letterLabel: 'Письмо на полномочие',
  },
  {
    id: 'p6',
    title: 'Настроить транспорт: ГОСТ TLS или СМЭВ4',
    text: 'Промышленный API ЕПГУ использует www.gosuslugi.ru по ГОСТ TLS. lk.gosuslugi.ru ниже относится только к пользовательским согласиям.',
    envKey: 'svcdev_host',
    url: 'https://www.gosuslugi.ru',
    linkLabel: 'ЕПГУ, промышленный контур',
    extraLinks: [
      {
        url: 'https://info.gosuslugi.ru/docs/section/%D0%A1%D0%9C%D0%AD%D0%92_4_(%D0%9F%D0%9E%D0%94%D0%94)/',
        label: 'Документы СМЭВ4 / ПОДД',
      },
      { url: 'https://partners.gosuslugi.ru/catalog/api_for_gu', label: 'Каталог API Госуслуг' },
    ],
  },
];

/** Ссылки, не привязанные к конкретному шагу. */
export const REFERENCE_LINKS = [
  { env: 'test', envKey: 'esia_host', url: 'https://esia-portal1.test.gosuslugi.ru/', label: 'ЕСИА, тест' },
  { env: 'test', envKey: 'svcdev_host', url: 'https://svcdev-gostapi.test.gosuslugi.ru/', label: 'ЕПГУ SVCDEV API' },
  { env: 'test', envKey: 'agreements', url: 'https://svcdev-betalk.test.gosuslugi.ru/settings/third-party/agreements/acting', label: 'Согласия пользователя, тест' },
  { env: 'prod', envKey: 'esia_host', url: 'https://esia.gosuslugi.ru', label: 'ЕСИА, прод' },
  { env: 'prod', envKey: 'svcdev_host', url: 'https://www.gosuslugi.ru', label: 'ЕПГУ API, прод' },
  { env: 'prod', envKey: 'agreements', url: 'https://lk.gosuslugi.ru/settings/third-party/agreements/acting', label: 'Согласия пользователя, прод' },
  { env: 'both', url: 'https://partners.gosuslugi.ru/catalog/esia', label: 'Материалы по ЕСИА' },
  { env: 'both', url: 'https://sc.digital.gov.ru/', label: 'Ситуационный центр электронного правительства' },
];
