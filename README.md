# protoledger-backend

Движок проекта [protoledger](https://github.com/protoledger/protoledger). Запуск всего продукта и описание — в основном репозитории.

## Разработка

```bash
cargo run -- serve --port 8080
cargo test
cargo clippy --all-targets -- -D warnings
```

## API

- Контракт: [`openapi.yaml`](openapi.yaml)
- Описание для людей: [`API.md`](API.md)
- Интерактивно: http://localhost:8080/api/docs
