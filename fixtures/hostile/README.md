# Злые записи

Намеренно кривые файлы для проверки устойчивости разборщиков (`plan/security.md` §7, шаг демо 14). Сгенерированы `pl-hostile`, руками не править — тест `committed_files_are_up_to_date` сверяет их с генератором.

```bash
cargo run -p pl-hostile -- --out fixtures/hostile              # перегенерировать
cargo run -p pl-hostile -- --out /tmp/large --large            # крупные записи (в репозиторий не кладём)
BLESS=1 cargo test -p pl-hostile --test hostile hostile_samples # обновить expected.json (результат просмотреть глазами)
FUZZ_ITERATIONS=200000 cargo test -p pl-hostile --release mutated_real   # длинный прогон мутаций
```

`expected.json` — итог разбора каждого файла: либо ошибка (`not_capture`, `limit_exceeded`), либо число кадров, сегментов, соединений, самый длинный поток, байты дыр и диагностика по кадрам. Тесты проверяют:

- `pl-hostile` — конвейер `pl-capture` → `pl-reassembly`: без паник и зависаний, итог совпадает с эталоном, заявленные «4 ГиБ» и скачки seq не выделяют память, 100 тысяч соединений даёт `limit_exceeded`, 100 тысяч сегментов по байту собираются за разумное время;
- мутации настоящих записей (случайные порчи, обрезка, вставки) не роняют разбор;
- `pl-server` — каждый файл через `POST /api/sources`: задача завершается, ошибки — `413` или `422` с текстом, сервер продолжает отвечать, байты потоков читаются.

| Группа | Файлы |
|---|---|
| Не запись | `empty`, `text`, `png-as-pcap`, `pcap-header-cut` |
| Контейнер pcap | `pcap-no-packets`, `pcap-last-record-cut`, `pcap-caplen-huge`, `pcap-caplen-over-snaplen`, `pcap-snaplen-zero`, `pcap-zero-length-frames`, `pcap-unknown-linktype`, `pcap-timestamps-wild` |
| Контейнер pcapng | `pcapng-block-length-{zero,huge,unaligned}`, `pcapng-epb-without-idb`, `pcapng-unknown-linktype`, `pcapng-captured-len-lies`, `pcapng-trailing-garbage`, `pcapng-two-shb` |
| Заголовки IPv4/TCP/Ethernet | `ipv4-ihl-*`, `ipv4-total-length-*`, `ipv4-version-6-in-ipv4-frame`, `tcp-offset-*`, `tcp-all-flags`, `ethernet-runt`, `ethernet-truncated-ip` |
| Поведение TCP | `tcp-seq-jump-1gib` (дыра как метаданные), `tcp-seq-jump-2gib` (ровно 2^31 — «старые» данные по RFC 9293, сегменты не учитываются), `tcp-seq-wrap`, `tcp-overlap-storm`, `tcp-many-connections`, `tcp-data-after-rst` |
| Содержимое | `payload-hostile-strings`: HTML, JS, управляющие символы и RTL в потоке — везде показывать как текст |
