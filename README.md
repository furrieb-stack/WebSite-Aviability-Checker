# SAC — Site Availability & Security Checker

```
   ███████╗███████╗██╗  ██╗    ██╗   ██╗███████╗██████╗
   ██╔════╝██╔════╝╚██╗██╔╝    ╚██╗ ██╔╝██╔════╝██╔══██╗
   ███████╗█████╗   ╚███╔╝      ╚████╔╝ ███████╗██████╔╝
   ╚════██║██╔══╝   ██╔██╗       ╚██╔╝  ╚════██║██╔═══╝
   ███████║███████╗██╔╝ ╚██╗      ██║   ███████║██║
   ╚══════╝╚══════╝╚═╝   ╚═╝      ╚═╝   ╚══════╝╚═╝
```

CLI-тулка для проверки доступности сайтов и аудита безопасности. REPL-режим, красивые таблицы, русский язык.

**made by .furrieb**

---

## Установка

```bash
npm install
npm run build
```

## Запуск

```bash
npm start
# или
node dist/index.js
```

## Команды

| Команда | Алиасы | Описание |
|---------|--------|----------|
| `help` | h, ? | Список команд |
| `check <url>` | c, up | Проверка доступности (DNS, SSL, статус, WAF, tech stack) |
| `scan <url>` | s, fullscan | Полный скан (всё ниже + рейтинг A-F) |
| `dirs <url>` | d, paths | Перебор ~160 путей |
| `headers <url>` | hd | Анализ security-заголовков |
| `vuln <url>` | v | Тест уязвимостей |
| `push <url>` | p, exploit | PUSH — агрессивное тестирование авторизации |
| `geo <url> [ping\|http\|tcp]` | g, world | Проверка из разных стран (check-host.net) |
| `guide <type>` | gd | Гайд по эксплуатации и защита |
| `log [open\|path\|clear]` | l | Логи / отдельная консоль |
| `clear` | cls | Очистка экрана |
| `about` | info, ver | О тулке |
| `exit` | quit, q | Выход |

## Русская раскладка

Как в SA-MP — если набираешь `рудз`, тулка понимает это как `help`. Полная таблица:

| RU | EN | RU | EN | RU | EN |
|----|-----|----|-----|----|-----|
| рудз | help | ысфт | scan | зышщ | push |
| срусл | check | вшкы | dirs | руфвукы | headers |
| мгдт | vuln | пущ | geo | дщп | log |
| фыщге | guide | сдущ | clear | учше | exit |

## Сканнер уязвимостей

| Тип | Пейлоады | Метод детекта |
|-----|----------|---------------|
| XSS | 30 | Reflected + pattern matching |
| SQLi | 30+ | Error-based + time-based blind |
| LFI | 33 | Pattern matching (passwd, environ, logs) |
| SSRF | 24 | Internal response diff + metadata patterns |
| CMDi | 30 | Output pattern matching (uid, files) |
| Path Traversal | 12 | File content patterns |
| Open Redirect | 13 paths × 10 params | Location header check |
| InfoLeak | 22 paths | Content pattern matching |

## PUSH режим

Агрессивное тестирование авторизации и обход защиты:

- **Default credentials** — 40+ комбинаций (WordPress, phpMyAdmin, Jenkins, Tomcat, MongoDB, Redis, Grafana, RabbitMQ...)
- **SQLi auth bypass** — 9 пейлоадов на login-формах и API
- **JWT bypass** — alg=none, None, NONE + role escalation
- **Header bypass** — X-Forwarded-For, X-Original-URL, Basic auth, Cookie injection (13 заголовков)
- **Path bypass** — ..;/, %2e, null-byte, case flip, trailing slash
- **Method bypass** — PUT, PATCH, DELETE, TRACE, OPTIONS
- **NoSQL injection** — $ne, $gt, $regex, $where
- **Mass assignment** — role=admin, isAdmin=true, user_type=admin

## Гайды

`guide <тип>` — подробные инструкции по эксплуатации и защите для каждого типа уязвимости:

XSS, SQLi, LFI, RFI, SSRF, CMDi, PathTraversal, OpenRedirect, InfoLeak, AuthBypass, WAF

Каждый гайд содержит: описание, пошаговую эксплуатацию, рекомендации по исправлению, ссылки на OWASP/CWE.

## Geo-check

Проверка доступности сайта из разных точек мира через [check-host.net](https://check-host.net) API:

```bash
geo example.com http     # HTTP-проверка из ~15 нод
geo example.com ping     # ICMP ping
geo example.com tcp      # TCP connect
```

Ноды: USA, Germany, France, Netherlands, UK, Japan, Singapore, Australia, Brazil, Russia, India, Canada, Sweden, Poland.

## Логи

Все результаты пишутся в `sac-logs/sac-<timestamp>.log`.

- `log` — показать последние 50 записей
- `log open` — открыть отдельную консоль с live-логами
- `log path` — путь к файлу логов
- `log clear` — очистить лог

## Разработка

```bash
npm run dev       # запуск через ts-node
npm run build     # сборка в dist/
```

## Лицензия

MIT
