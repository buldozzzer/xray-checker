# xray-checker

Проверка доступности серверов из подписки remnawave через ядро xray с веб-матрицей результатов.

## Запуск

```bash
pip install -r requirements.txt
# бинарь xray: bin/xray (Xray-linux-64.zip с github.com/XTLS/Xray-core/releases)
SUB_URL=https://... PORT=8090 python3 app.py
```

Открыть http://localhost:8090

## Docker

```bash
cp .env.example .env   # указать SUB_URL
docker compose up -d --build
```

Интерфейс: http://localhost:8090 (порт хоста меняется через `HOST_PORT`). xray скачивается при сборке образа, версию можно сменить: `docker compose build --build-arg XRAY_VERSION=v26.3.27`. Остальные переменные (см. ниже) задаются в `.env` рядом с `docker-compose.yml` или в окружении.

## Как работает

1. Подписка запрашивается с `User-Agent: Happ/5.6.0/ios/2608171408551` — remnawave отдаёт массив полных xray-конфигов.
2. Из каждого конфига берутся proxy-outbound'ы (vless/trojan/hysteria/…); если в конфиге их несколько (балансер) — каждый становится отдельной ячейкой.
3. Запускается один процесс xray: на каждый сервер свой HTTP-inbound `127.0.0.1:20000+N`, роутинг inbound → outbound. Роутинг из подписки не используется. Если xray отвергает какой-то outbound, он помечается ошибкой, остальные работают.
4. Проверка — GET через локальный прокси, новое соединение на каждый запрос, таймаут 60 с. Время включает рукопожатие с сервером.

Цели: YouTube (`/generate_204`), `proof.ovh.net/files/1Mb.dat` (показывает Мбит/с), `cp.cloudflare.com/generate_204`, `api.ipify.org` (показывает выходной IP).

## Переменные окружения

| Переменная | По умолчанию |
|---|---|
| `SUB_URL` | URL подписки (обязательно) |
| `SUB_USER_AGENT` | `Happ/5.6.0/ios/2608171408551` |
| `XRAY_BIN` | `bin/xray` |
| `XRAY_BASE_PORT` | `20000` |
| `CHECK_TIMEOUT` | `60` |
| `CHECK_CONCURRENCY` | `24` |
| `AUTO_CHECK_INTERVAL` | `0` (выкл.), секунды между автопроверками всех целей |
| `HOST` / `PORT` | `0.0.0.0` / `8080` |
