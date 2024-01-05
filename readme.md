## Простой пример работы с ЕСИА и ЕПГУ

Сервис для автоматизации процесса подачи заявлений и обработки результатов 
[API Госуслуг](https://partners.gosuslugi.ru/catalog/api_for_gu)

## CryptoPro
[CriptoPro](https://cryptopro.ru/user/login?destination=system)
в частности здесь используеться версия csp/50/12997rc2 linux-amd64_deb.tgz
и версия PyCades взятая с [pycades](https://cryptopro.ru/sites/default/files/products/cades/pycades/pycades.zip) 0.1.44290
немного новее чем устанавлеваемая через

```bash
pip install pycades
```

### Проверка существующих крипто-контейнеров:
```bash
csptest -keyset -enum_cont -verifycontext -fqcn
```

### Установка корневого сертификата:
```bash
certmgr -inst -store root -file <путь к файлу с сертификатом>
```

### Установка личного сертификата:
```bash
certmgr -inst -file <путь к файлу с сертификатом> -cont <имя контейнера>
```

### Установка стороннего сертификата:
```bash
certmgr -inst -file <путь к файлу с сертификатом>
```

### Примеры приложений, работающих с /opt/cprocsp/src

[Документация разработчикак продуктам КриптоПро](https://docs.cryptopro.ru/)

[Работа с ключами и сертификатами](https://www.cryptopro.ru/category/faq/linuxunix/rabota-s-klyuchami-i-sertifikatami)

## Dockerfile

Собираем базовый образ

## Compose

Порт для отладки 5678.
Для продуктивной среды и/или какой либо еще оркестрации лучше использовать секреты и иные способы хранения чувствительной информации и передачу ее в контейнер в виде переменных среды и/или готовых файлов. 
открепленный ключ можно скопировать в папку XXX.000 или определить переменную среды key_folder. Либо вовсе исправить compose файл.

## Как развернуть в Kubernetes

Перед развертыванием с помощью Helm или запуском первого конвейера CICD:

1. Создаем namespace

```bash
kubectl create namespace epgu-dev
```

1. Создаем secret на главном узле (master node) в новом namespace:

```bash
kubectl -n epgu-dev create secret tls tls-epgu-secret --key epgu-ingress-cert/private/epgu-dev.ru.key.pem --cert epgu-ingress-cert/certs/chain-epgu-dev.ru.cert.pem
```

1. Создаем configmaps

```bash
kubectl create configmap test-keys --from-file header.key --from-file masks.key --from-file masks2.key --from-file name.key --from-file primary.key --from-file primary2.key 

kubectl create configmap test-certs --from-file=some.cer --from-file=test_ca_rtk2.cer 
```

После выполнения предварительных требований вы можете выполнить развертывание вручную (с помощью команды ниже) или запустить конвейер CI CD (например нажать кнопку «Запустить конвейер» в Gitlab или внесите изменения), здесь используеться приватный репозиторий docker:

```bash
helm upgrade --install epgu . --set hostname=dev --set repo=docker-registry.local:5000 --set ProjectName=epgu/systems/epgu --set ImageTag=dev
```

## Как протестировать

```bash
POST http://epgu.epgu-dev.ru/accessTkn_esia 
```
(dev example, укажите правильный ingress host) с параметром JSON {"api_key": ""} в body. Вы должны получить token.


## Postman

коллекция в файле postman.json в корне проекта

## Описание работы с ЕСИА и ЕПГУ

Фактически, такая  работа с API Госуслуг предназначена для физических лиц и  для организаций НЕ имеющих возможность подклключиться к СМЭВ, сводиться к возможности авторизации через ЕСИА (Единая система идентификации и аутентификации) отправки 4 запросов к ЕПГУ (Единого портала государственных и муниципальных услуг ) 
[Спецификация API ЕПГУ](https://gu-st.ru/content/partners/api_for_gu/Specifikaciya_API_EPGU_v1_12.docx)

1. Создание заявления 
```/api/gusmev/push```

1. Загрузка файла 
```/api/gusmev/push``` 

1. Загрузка файлов вложения
```/api/gusmev/push/chunked```

2. Получение данных по заявлению
```order/{{orderId}}?embed```

Для каждой из услуг имееться своя спецификация по заполнения запросов, но в основном все отличия в полях XML.
