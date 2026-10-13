# protoledger-backend

Движок проекта [protoledger](https://github.com/protoledger/protoledger): чтение записей трафика, сборка TCP-потоков, описание протокола и его проверка на корпусе, локальный API и командная строка. Запуск всего продукта, установка и сценарии — в основном репозитории.

## Разработка

Нужен Rust stable (см. `rust-toolchain.toml`).

```bash
cargo run -p protoledger -- serve --port 8080
# с Swagger UI и dev-режимом для фронта
PROTOLEDGER_DEV_TOKEN=dev-token-123 cargo run -p protoledger --features dev-tools -- serve --dev
cargo test --workspace --features protoledger/dev-tools
cargo clippy --workspace --all-targets --features protoledger/dev-tools -- -D warnings
```

## Структура

Зависимости идут сверху вниз; библиотеки разбора не знают про HTTP, проект и интерфейс.

| Крейт | Что делает |
|---|---|
| `protoledger` | Командная строка: `serve`, `apply`, `draft`, `coverage`, `compare`, `graph`, `verify`, `report`, `bench` |
| `pl-server` | Локальный HTTP API, защита запросов, раздача встроенного интерфейса |
| `pl-app` | Сценарии поверх библиотек: импорт, прогон, тесты гипотез, подсказки, задачи с прогрессом и отменой |
| `pl-project` | Папка проекта на диске: манифест, неизменные копии записей, ревизии, прогоны; атомарная запись |
| `pl-capture` | Чтение pcap и pcapng, индекс кадров, разбор Ethernet, IPv4, TCP |
| `pl-reassembly` | Сборка TCP: соединения, направленные потоки, карта участков (данные, дыры, неоднозначности) |
| `pl-interp` | Описание протокола: схема, язык выражений, фрейминг, разбор полей |
| `pl-verify` | Прогон на корпусе: сводка, контрпримеры, сравнение прогонов, устаревание |
| `pl-analysis` | Подсказки: границы сообщений, изменчивость байтов, связи с журналом, пары запрос→ответ |
| `pl-actions` | Журнал действий: CSV с сопоставлением колонок и времени |
| `pl-report` | Отчёт Markdown и HTML |
| `pl-core` | Общий формат ошибок API |
| `protoledger-desktop` | Настольное приложение (Tauri): окно со встроенным движком; отдельный workspace |
| `pl-synth`, `pl-stand`, `pl-hostile` | Только для тестов: синтетические записи с дефектами захвата, учебное устройство с журналом, злые входы |

## API

- Контракт: [`openapi.yaml`](openapi.yaml); описание для людей: [`API.md`](API.md).
- Интерактивно, только в dev-сборке: http://localhost:8080/api/docs.
- Командная строка: [`docs/cli.md`](docs/cli.md). Правила сборки TCP: [`docs/reassembly.md`](docs/reassembly.md).

## Проверки

| Что | Как |
|---|---|
| Тесты библиотек и API | `cargo test --workspace --features protoledger/dev-tools` |
| Ответы API соответствуют схемам контракта | тест `contract` в `pl-server` |
| Заведомо кривые запросы по всем путям контракта не дают ошибок сервера | тест `sweep` в `pl-server` |
| Злые записи, журналы, описания, манифесты: итог каждого совпадает с ожидаемым | `fixtures/hostile`, тесты `pl-hostile` |
| Сборка потоков совпадает с `tshark` | `PL_REQUIRE_TSHARK=1 cargo test -p pl-reassembly --test tshark` |
| Фаззинг разборщиков | [`fuzz/`](fuzz/README.md), workflow `fuzz` |
| Время и память на контрольном профиле | `protoledger bench`, workflow `bench` |

Тестовые данные лежат в `fixtures/` и создаются генераторами; тесты сверяют файлы с генераторами, руками их не правят.
