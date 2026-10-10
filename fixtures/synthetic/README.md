# Синтетические записи

Сгенерированы `pl-synth` (seed 1). Не править руками — тест `fixtures_are_up_to_date` сверяет их с генератором.

```bash
cargo run -p pl-synth -- list
cargo run -p pl-synth -- generate --out fixtures/synthetic
cargo run -p pl-synth -- generate --out fixtures/synthetic --format pcap normal
```

| Файл | Ситуация (ТЗ 7.3) |
|---|---|
| `normal` | рукопожатие, обмены, два сообщения в одном сегменте, сообщение в двух сегментах, FIN; есть и `.pcap` |
| `reorder` | сегменты не по порядку, seq клиента переходит через 2^32 |
| `duplicates` | одинаковые повторы |
| `gap-truncation` | потерянный сегмент и усечение snaplen (160) |
| `overlap-conflict` | перекрытие с разными байтами и с теми же |
| `no-handshake` | нет SYN: роли и начало потоков неизвестны |
| `bad-checksum` | offloading: неверные TCP-суммы у всех кадров одного узла |
| `port-reuse` | три соединения с одним 4-кортежем (после FIN, после RST) |
| `background` | ARP, UDP, IPv6, фрагменты IPv4 — пропуск с диагностикой |
| `interpretation.yaml` | описание границ сообщений синтетических записей (для `protoledger bench`) |
| `mixed` | два параллельных соединения со всеми дефектами и фоном |

## Эталон `<имя>.expected.json`

Результат при политиках по умолчанию (`overlap: first`, `checksum: warn`). Номера кадров — с 1.

- `skipped` — кадры вне Ethernet/IPv4/TCP и фрагменты, `kind`: `arp`, `udp`, `ipv6`, `ipv4-fragment`.
- `badChecksumFrames`, `offloadingHost` — неверные суммы и узел с offloading.
- `connections` — по первому кадру; `rolesKnown` — захвачен SYN или SYN-ACK.
- Поток направления: смещения от ISN+1 (`startKnown: true`) или от первого захваченного сегмента с данными. `length` — с дырами, `sha256` — известных байтов подряд, `gaps`, `ambiguous` (с кадрами-кандидатами), `duplicateFrames`, `messages` — истинные границы сообщений `[A5][тип][длина u16 BE][тело]`.

Кадры короче 60 байт дополнены нулями: длину брать из заголовка IPv4.
