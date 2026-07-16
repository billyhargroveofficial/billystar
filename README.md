# shadowpipe

Проприетарный encrypted tunnel: Rust, ML-KEM-768 + X25519, ChaCha20-Poly1305.

## Целевая топология

- production `shadowpipe-server` запускается только на Linux VPS;
- общий Rust protocol/crypto/packet core используется всеми сборками;
- production-клиенты: Linux TUN, macOS Network Extension и Windows
  Wintun/WFP;
- переносимый no-TUN server разрешён только как явный loopback/VM
  development harness и не является поддерживаемым server deployment target.

Сейчас Linux — единственная платформа со scoped full-TUN implementation
evidence. Windows подтверждён только в no-TUN portability cell, а native
macOS/Windows system-VPN backends остаются открытыми gates.

## Что есть

| Phase | Фичи |
|-------|------|
| **0** | PQ handshake, encrypted frames, padding, echo mode |
| **1** | TUN/data-plane code для Mac/Linux/Windows, stream mux и IP tunnel; synthetic OrbStack Linux IPv4 OS-TUN/leak/cut/recovery proof — PASS, native Windows/macOS TUN и IPv6 matrices остаются отдельными gates |
| **2** | **h2-chunk** camouflage, Linux-first fail-closed **auto-route**, persistent server keys и VPS deploy; synthetic Linux IPv4 runtime gate закрыт, production/field gate — нет |
| **3** | Строгая подписанная endpoint-policy v2, bounded live DNS/endpoint transactions, durable REALITY replay admission и crash-safe Linux host-state WAL/recovery; current-source Linux ARM64, Linux full-TUN/crash/reboot и Windows ARM64 no-TUN matrices — scoped PASS |

## Phase 3: production-safety mechanisms, не production claim

Phase 3 добавляет safety plane для подписанных REALITY endpoints и Linux host
state:

- root-signed keyset v1 + online-signed endpoint-policy v2 в фиксированном
  `COSE_Sign1`/deterministic-CBOR/Ed25519 profile, с persistent anti-rollback,
  expiry и rotation. Новый policy подписывает только `Active` online key;
  exact sorted `service_id` set неизменен после enrollment, а смена key/pin
  требует полного 86,400-second overlap, включая lifetime policy/key/pin;
- отдельный подписанный `locator_name` для DNS и независимый REALITY `sni`;
  policy v1 отвергается явно, без compatibility fallback;
- DNS может только сузить уже подписанное множество IPv4. Изменения проходят
  транзакционно `firewall allow -> /32 route -> publish`; cleanup идёт в
  обратном направлении и уважает leases открытых sockets;
- при полном outage один раз на failure epoch восстанавливается полное
  подписанное address authority без underlay DNS; tunneled DNS возобновляется
  только после успешного carrier;
- bounded anchored WAL охватывает TUN, routes, static/dynamic firewall и DNS
  exchange. Startup recovery выполняется до policy/DNS/socket/TUN и fail closed
  при неполном доказательстве ownership;
- orderly policy expiry записывает отдельный fixed-size `SPPOLEX1` tombstone,
  который блокирует повтор того же policy hash после rollback wall clock;
- production TUN непостоянный: crash recovery никогда не удаляет интерфейс по
  имени или ifindex. И клиент, и сервер создают explicit named Linux TUN с
  `IFF_TUN_EXCL`; route/firewall helpers имеют deadline, output cap,
  process-group kill и reap;
- production REALITY admission использует HMAC-authenticated, static-key-bound
  fixed 1,572,960-byte replay store с exclusive lease и durable commit до
  accepted flight.

Точный protocol, failure ordering и границы доказательств описаны в
[`docs/phase3-production-safety.md`](docs/phase3-production-safety.md). На
2026-07-16 запечатаны пять current-source evidence bundles:

- native Linux ARM64 portability:
  [`20260716T122834Z-linux-arm64-current`](tests/portability/results/20260716T122834Z-linux-arm64-current/RESULT.md),
  `PASS`, 342/342 checksum entries; frozen source manifest 187/187, SHA-256
  `fd5ebffc5b820ec8ac037aa3e9fea154c62576d7a276fa923168e5f4b4a84b95`;
- full-TUN/REALITY IPv4 netns:
  [`20260716T123535Z-91294-70zWb7`](tests/tun/results/20260716T123535Z-91294-70zWb7/RESULT.md),
  `PASS`, 573/573 checksum entries, включая foreign named-TUN collision;
- same-boot schema-v3 all-resource SIGKILL/recovery:
  [`20260716T124109Z-93828`](tests/host-recovery/results/20260716T124109Z-93828/FINAL-RESULT.md),
  `PASS`, 29/29 scenarios and 1443/1443 checksum entries;
- early-userspace reboot lockdown:
  [`20260716T124706Z-34564-reboot`](tests/lockdown/results/20260716T124706Z-34564-reboot/RESULT.md),
  `PASS`, distinct boot IDs and 650/650 checksum entries;
- Windows 11 ARM64 H2 no-TUN:
  [`20260716T125113Z-36840-dd0c2571`](tests/windows/results/20260716T125113Z-36840-dd0c2571/RESULT.md),
  `PASS`, 891/891 checksum entries.

Это implementation evidence, не production/field claim. Crash matrix моделирует
same-boot process death через `SIGKILL`, а не power loss; reboot cell проверяет
только ранний Linux L3 OUTPUT barrier и explicit release, без paired tunnel.
Windows cell — no-TUN private-socket portability, не Wintun/leak proof. IPv6,
native Windows/macOS TUN, field censorship evidence, independent cryptographic
review и causal activation остаются открыты. Старые bundles остаются
историческими/диагностическими и не заменяют current-source результаты выше.
Policy signatures use classical Ed25519: they authenticate endpoint authority
and pin rotation, not post-quantum control-plane security or causal-evidence
producer provenance.

Важно: overlap защищает continuity rollout, но не скомпрометированный `Active`
online signer. Такой signer всё ещё может авторизовать новый attacker-controlled
pin рядом со старым. Для containment нужен отдельный offline-root/threshold
service-auth registry; текущая v2 policy этого не заявляет.

## Быстрый тест (без root)

```bash
./scripts/test-local.sh
```

## Сборка

```bash
SHADOWPIPE_MAGIC=0xdeadbeef cargo build --release  # один magic для client+server
cargo build                                      # debug/test: random local magic допустим
```

`SHADOWPIPE_MAGIC` — wire-compatibility value, а не секрет. Если client и server
собираются отдельно (другой target/OS/CI job), release pipeline обязан
передать им **одно и то же** явное 32-bit значение и записать его в
artifact manifest. Release build без `SHADOWPIPE_MAGIC` теперь fail closed.
Random magic остаётся только удобством debug/test profile: каждый свежий target
может получить другой magic и не считается совместимым с независимой сборкой.
Невалидное значение также останавливает build, а не молча создаёт другой
protocol identity.

Windows 11 ARM64 no-TUN client собирается через Zig только с явным
общим magic:

```bash
SHADOWPIPE_MAGIC=0x50334852 ./scripts/cross-build-windows-arm64.sh
```

Скрипт печатает target, magic, SHA-256, size и artifact path для
release/experiment manifest. Эта сборка не содержит default
`tls-chrome`/BoringSSL carrier; для неё проверены raw/h2 no-TUN paths.

## Echo

Protocol v3 has no anonymous/open mode. Prepare a rootless loopback identity and
commit its one-time enrollment artifact before starting either endpoint:

```bash
install -d -m 0700 .shadowpipe/dev-auth
cargo run -p shadowpipe-client -- \
  --development-user-credential --generate-client-credential \
  --client-credential "$PWD/.shadowpipe/dev-auth/client.json" \
  --write-client-enrollment "$PWD/.shadowpipe/dev-auth/enrollment.json"
cargo run -p shadowpipe-server -- \
  --development-user-allowlist \
  --client-allowlist "$PWD/.shadowpipe/dev-auth/allowlist.json" \
  --enroll-client "$PWD/.shadowpipe/dev-auth/enrollment.json"

# server выводит `server-fp: ...`; передайте его клиенту как SERVER_FP
# raw (explicit; CLI default is h2)
cargo run -p shadowpipe-server -- \
  --development-user-allowlist --allow-insecure-lab-carriers \
  --client-allowlist "$PWD/.shadowpipe/dev-auth/allowlist.json" \
  --keys "$PWD/.shadowpipe/dev-auth/server-keys.json" \
  --listen 127.0.0.1:47843
cargo run -p shadowpipe-client -- \
  --development-user-credential \
  --client-credential "$PWD/.shadowpipe/dev-auth/client.json" \
  --server 127.0.0.1:47843 --server-fp SERVER_FP --camouflage raw --message hello

# h2 camouflage — wire выглядит как HTTP/2 DATA
cargo run -p shadowpipe-client -- \
  --development-user-credential \
  --client-credential "$PWD/.shadowpipe/dev-auth/client.json" \
  --server 127.0.0.1:47843 --server-fp SERVER_FP --camouflage h2 --message hello
```

Raw/H2/TLS/QUIC daemon carriers are intentionally restricted to this explicit
user-owned, no-TUN lab mode: an active probe can distinguish their ShadowPipe
bootstrap/challenge even though the mutual PSK gate emits no ML-KEM key or KEM
work before authorization. A normal daemon and every full-tunnel deployment
require REALITY.

Enrollment не содержит Ed25519 private seed, но содержит независимый 256-bit
PSK и потому остаётся secret transfer artifact. Удалите его после успешного
enrollment. Credential/PSK не передаются через URI, argv, environment или logs.
Normal start требует root-owned single-link `0600` credential/allowlist.
Ротация: enroll new → проверить новый client → revoke old; последнюю запись
server удалить не позволяет.

## Tunnel (root)

### VPS deploy

```bash
# сначала на КЛИЕНТЕ (никогда не генерировать client credential на VPS):
sudo install -d -o root -g root -m 0700 /etc/shadowpipe
sudo shadowpipe-client --generate-client-credential \
  --client-credential /etc/shadowpipe/client-credential.json \
  --write-client-enrollment /root/client-enrollment.json
sudo scp /root/client-enrollment.json root@VPS:/root/client-enrollment.json

# затем на VPS; allowlist commit/validation предшествует NAT/service start:
sudo ./deploy/install-vps.sh --port 47843 --egress eth0 \
  --binary /tmp/shadowpipe-server \
  --client-enrollment /root/client-enrollment.json
sudo shadowpipe-server --nat-hint --egress-iface eth0
# → iptables NAT
```

Ключи: `/etc/shadowpipe/keys.json` (переживают рестарт). Сервер печатает свой
**fingerprint** при старте и по `--gen-keys`: `server-fp: <64-hex>` — он нужен клиенту.
`--gen-keys` и `--gen-reality-key` idempotently загружают existing identity или
create-only создают отсутствующую; они никогда не выполняют неявную pin-breaking rotation.
Production server также требует effective UID 0 и root-owned, не
group/world-writable, non-symlink ancestors для обоих identity paths; rootless
loopback использует только явный `--development-user-allowlist` и такие же
non-writable user-owned ancestors.

Installer проверяет enrollment/allowlist новым staged binary до атомарной смены
installed binary/unit и до sysctl/iptables/service start. Ошибка на existing v3
оставляет старый runtime нетронутым; rollback удаляет только добавленные этим
run правила и возвращает его artifacts. Pre-v3/unverifiable active runtime при
миграции сначала останавливается и при ошибке намеренно не воскресает: downtime
безопаснее продолжения потенциального open relay.
Installer также отвергает legacy broad inbound `FORWARD ... -d 10.8.0.0/24
-j ACCEPT`; удалите его явно перед retry. Новая return rule допускает только
conntrack `RELATED,ESTABLISHED`, а rollback удаляет её лишь если создал в этом run.

### Аутентификация сервера (anti-MITM) — обязательно

Цензор по определению on-path. Без пина клиент шифрует к ЛЮБОМУ ключу с провода →
активный MITM. Клиент обязан пинить статический ML-KEM-ключ сервера:

```bash
# на сервере — получить fingerprint:
shadowpipe-server --gen-keys --keys /etc/shadowpipe/keys.json
# → server-fp: be8fdb5fc5b51a5ca0180d1b7281d5ce3be3f104884603c6e7e4d621ecc133da
```

Клиент передаёт его через `--server-fp` либо через `fp=` в каждом REALITY URI.
Во всех текущих режимах pin обязателен: отсутствие или malformed value отвергаются
до reservation trace, DNS, socket и TUN; mismatch обрывает inner handshake до
ML-KEM encapsulation и ClientHello (mutual PSK access flights уже прошли).
Unpinned режима, включая lab,
нет. Fingerprint надо получать из независимо аутентифицированного server log или
artifact manifest, а не из той же неаутентифицированной сессии.

### Full-tunnel client — isolated Linux host/VM

> **Host-safety gate:** commands containing `--auto-route`, `--kill-switch` or
> `--dns` mutate host networking. Current fail-closed `--auto-route` is
> Linux-only and must be tested in an isolated Linux VM/host with a rollback
> path. Never run these examples on the current Mac while its production
> `sing-box` is live.

```bash
sudo install -o root -g root -m 0600 \
  /securely-delivered/shadowpipe.uri /etc/shadowpipe/endpoint.uri
sudo shadowpipe-client \
  --client-credential /etc/shadowpipe/client-credential.json \
  --uri-file /etc/shadowpipe/endpoint.uri \
  --tunnel \
  --ipv6-mode block \
  --auto-route \
  --kill-switch \
  --dns 1.1.1.1 \
  --mux-streams 24
```

`--auto-route` сейчас принимается только на Linux и обязательно требует
`--tunnel --kill-switch --dns <TUN_RESOLVER>`. Невалидная комбинация отвергается
до DNS/socket/TUN или host mutation. Затем kill-switch включается до смены
маршрутов, ставятся carrier/SSH bypass routes, split-default
(`0.0.0.0/1` + `128.0.0.0/1`) и DNS pin. Это реализованный fail-closed порядок и
unit-test evidence. В disposable OrbStack Linux clone этот порядок также прошёл
privileged synthetic IPv4 OS-TUN/leak/failure/recovery/cleanup proof; точный scope
и ограничения записаны ниже и в
[`20260716T123535Z-91294-70zWb7`](tests/tun/results/20260716T123535Z-91294-70zWb7/RESULT.md).
`--ipv6-mode block` является default и явно указан в production examples:
текущий Linux kill-switch блокирует non-loopback IPv6 до публикации IPv4
маршрутов. `outer-only` и `tunnel` fail closed до credential, DNS, socket, TUN
или host-state операций, пока соответствующие backends не реализованы.

## REALITY carrier (TLS 1.3 + forward-on-fail probe handling)

From-scratch **TLS 1.3 + REALITY** (`crates/shadowpipe-reality`, вкручен через
`--reality`). На wire — настоящий TLS 1.3 handshake к `--sni`; а
**неаутентифицированный пир форвардится на реальный cover-сайт** и в проверенных
integration tests получает его ответ (forward-on-fail). Это уменьшает один класс
наивного active probing, но не доказывает эквивалентность прямому cover-соединению
или неотличимость: endpoint/SNI, timing, failure behavior, TLS-in-TLS и cross-flow
признаки остаются. PQ-сессия shadowpipe (ML-KEM+X25519, pin) идёт **внутри**
REALITY.

`--outer-handshake-timeout-secs` ограничивает только классификацию rejected
ClientHello, cover connect и его write/flush. Уже установленный forward-to-cover
splice живёт вне этого absolute deadline под отдельным sliding
`--forward-idle-timeout-secs` (default 300 s): read/write progress в любом
направлении сбрасывает общий monotonic idle deadline, поэтому активный
асимметричный HTTP/2 download не обрывается через 15 секунд.

```bash
# сервер: один раз — private dirs, REALITY key, ML-KEM key и carrier token
sudo install -d -o root -g root -m 0700 /etc/shadowpipe
sudo install -d -o root -g root -m 0700 /var/lib/shadowpipe
sudo sh -c 'set -C; umask 077; openssl rand -hex 8 > /etc/shadowpipe/reality-short-ids'
sudo shadowpipe-server --gen-reality-key --reality-key /etc/shadowpipe/reality.key
sudo shadowpipe-server --gen-keys --keys /etc/shadowpipe/keys.json

# только explicit one-shot печатает secret-bearing URI; обычный daemon — нет:
#   reality-uri: shadowpipe://<pubkey>@host:port?sni=..&sid=..&fp=..
sudo shadowpipe-server --print-uri --reality --advertise VPS_IP:443 \
  --reality-key /etc/shadowpipe/reality.key --keys /etc/shadowpipe/keys.json \
  --reality-short-id-file /etc/shadowpipe/reality-short-ids \
  --cover www.microsoft.com:443

# production daemon читает token из root:0600 файла, не из argv
sudo shadowpipe-server --listen 0.0.0.0:443 --reality --advertise VPS_IP:443 \
  --reality-key /etc/shadowpipe/reality.key --keys /etc/shadowpipe/keys.json \
  --client-allowlist /etc/shadowpipe/client-allowlist.json \
  --reality-short-id-file /etc/shadowpipe/reality-short-ids \
  --reality-replay-store /var/lib/shadowpipe/reality-replay-v1.bin \
  --cover www.microsoft.com:443 --tunnel --egress-iface eth0

# securely transfer the one-line URI into a root-owned private file first;
# endpoint URI carries server/pubkey/sid/sni/fp, device credential is separate
sudo install -o root -g root -m 0600 \
  /securely-delivered/shadowpipe.uri /etc/shadowpipe/endpoint.uri
sudo shadowpipe-client --uri-file /etc/shadowpipe/endpoint.uri \
  --client-credential /etc/shadowpipe/client-credential.json \
  --tunnel --ipv6-mode block --auto-route --kill-switch --dns 1.1.1.1
```

`--uri-file` — production client path: он убирает `sid` и URI из
process argv. Loader до credential/lease/DNS/socket/TUN открывает final file
`O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`, ограничивает его 64 KiB и требует
trusted real non-group/world-writable ancestors и regular/single-link/exact
`0600` final file; tunnel/production дополнительно требует
effective UID 0 и root:root. `--uri` оставлен как explicit diagnostic
input и раскрывает selector в argv. URI sources нельзя смешивать друг с
другом, signed-policy или individual REALITY/pin flags. Во всех manual
client paths `sid` обязан быть ровно 16 lowercase hex (8 bytes).
URI query закрыт: ровно по одному `sni`/`sid`/`fp`, без duplicate и
unknown keys; low-order/non-contributory REALITY X25519 keys отвергаются до
credential и network startup.

`--reality-short-id-file` содержит 1..16 строго sorted unique строк, каждая ровно
16 lowercase hex (8 bytes); production loader требует trusted root-owned path,
final regular/no-follow/root:root/`0600`/single-link file. Это ротируемый online
carrier ACL, а не device identity. Inline `--reality-short-id` разрешён только в
explicit `--development-user-allowlist` no-TUN lab и конфликтует с
`--print-uri`/`--tunnel`.

`--reality-replay-store` — mutable root-private fixed-slot state, загружаемый до
listener bind. Production default:
`/var/lib/shadowpipe/reality-replay-v1.bin`; final data и `.lock` обязаны быть
root:root, single-link, exact `0600`, parent chain — trusted и
non-group/world-writable. Store HMAC-authenticated и связан с REALITY static
key; mismatch при rotation aborts startup, поэтому новый key получает новый
store/path только как явная coordinated rotation. Fresh token записывается и
`fdatasync`-ится до accepted REALITY flight; restart сохраняет replay rejection.
Corruption/full/I/O переводят carrier admission в forward-to-cover, а не в
accept. Это same-host guarantee: replicas без strongly consistent shared replay
state обязаны иметь уникальные REALITY static keys. В explicit user-owned
no-TUN development path store также задаётся явно; process-local fallback у
daemon отсутствует. Это не availability guarantee: владелец действительного
online `short_id` может форсировать sync work и заполнить 16,384 slots, после
чего валидные carrier attempts fail-forward до cover. Один local file также не
предотвращает cross-replica replay при общем static key.

`--cover`/`--sni` — правдоподобный сайт, на который сервер реально форвардит
неавторизованных (домен и SNI должны совпадать). На старте сервер профилирует
cover и подгоняет шифр+размер token-accepted flight под него (`--no-cover-profile` чтобы
выкл). Снаружи REALITY key + 64-bit token допускают carrier, но не device. Внутри
server первым доказывает device PSK, client отвечает только после проверки, и
ML-KEM key не выходит до client MAC; затем работают ML-KEM pin (`fp`) и
Ed25519+PSK Finished. Без
`--uri-file`/`--uri` те же значения задаются **client**-флагами
`--reality --reality-pubkey --reality-short-id --sni --server-fp`.

## TLS-chrome camouflage (boring-front)

Outer TLS реализован через **BoringSSL**. Для одной зафиксированной версии
инструмента ClientHello дал reference JA4 vector
`t13d1516h2_8daaf6152771_e5627efa2ab1` (`tools/ja4-gate` +
`tools/boring-front`). Это проверка одного ClientHello-признака, а не browser
behavioral parity и не доказательство неотличимости от Chrome. Inner framing
зашифрован outer TLS, но endpoint, certificate, timing, TLS-in-TLS и cross-flow
признаки остаются наблюдаемыми.

Этот carrier теперь **только no-TUN lab**: self-signed TLS endpoint не имеет
REALITY forward-on-fail и остаётся active-probe tell. Сервер запускается лишь с
`--development-user-allowlist --allow-insecure-lab-carriers --tls`; клиент — с
development credential и `--message`/`--loadtest`, без `--tunnel`. Production и
full-tunnel используют REALITY из предыдущего раздела.

TLS тут — **lab-камуфляж**: серт клиент НЕ проверяет, аутентификация по-прежнему
через пин ML-KEM-ключа (`--server-fp`, см. B1). `--sni` лучше указывать как
домен, который правдоподобно резолвится в этот сервер (иначе SNI/IP-mismatch —
сам по себе tell). `--camouflage` при `--tls` игнорируется (внутри raw-фрейминг).

**Защита от утечек (full-tunnel, Linux):** `--auto-route` без `--kill-switch` и
`--dns <ip>` теперь fail closed ещё на preflight. Kill-switch разрешает только
TUN, точные carrier endpoints и loopback; DNS guard
временно пинит `/etc/resolv.conf` на resolver внутри туннеля.

**Synthetic runtime proof, 2026-07-16.** Current-source run
[`20260716T123535Z-91294-70zWb7`](tests/tun/results/20260716T123535Z-91294-70zWb7/RESULT.md)
выполнен внутри disposable OrbStack clone и private Linux netns. Итог:

- `test_status=valid`, `cleanup_status=valid`, `host_safety_status=valid`,
  IPv4 only, `field_evidence=false`;
- production-gated REALITY URI/short-ID/pin + mandatory v3 credential/allowlist;
  unauthenticated stock-TLS probe был отправлен в synthetic cover, а до старта
  authenticated client число inner sessions оставалось нулевым;
- durable REALITY replay store был leased до bind: data file 1,572,960 bytes,
  отдельный lock и lifecycle marker были проверены и удалены только при
  private-state cleanup;
- planted persistent empty-alias TUN с тем же именем дал atomic
  `EBUSY`/`EEXIST` за 172 ms до host mutation: 0 underlay/carrier packets,
  foreign link/MTU/address/alias неизменны, WAL отсутствовал;
- ICMP 20/20; TCP receiver 561,905,664 bytes при 446.785 Mbit/s; UDP receiver
  5,092 packets, 0 lost; source/download 64 MiB дали один SHA-256
  `5ca1b38d0543084e1a1027831af37e3552e47ac34eb42bb8012c26ece4f67510`;
- tunneled DNS вернул synthetic `198.18.0.2`; strict non-carrier underlay,
  missing-credential и missing-pin captures дали `0/0/0`;
- TCP-reset cut не открыл direct fallback; восстановление завершилось с
  recorded upper bound 8 s; SIGTERM оставил durable L3/OUTPUT lockdown,
  после explicit release исчезли WAL и exact lockdown table;
- все 573/573 checksum entries прошли `sha256sum -c`; clone был удалён, а
  guest-root state и private resolver после cleanup сошлись с baseline.

Stable read-only Mac snapshots до/после совпали для routes, DNS, static PF
config/anchor files и exact identity живого sing-box. Это endpoint snapshots, не
continuous host mutation monitor. Загруженные runtime PF rules без host
privilege не наблюдались (`pf_runtime_observed=false`), поэтому их неизменность
не заявляется. OrbStack 2.2.1 в наблюдённом lab run паниковал при delete-by-ID:
runner запускал/адресовал guest по связанному opaque ID, а удаление по имени
разрешал только после немедленного name-to-ID rebind и затем доказывал
отсутствие ID и имени. Unrelated same-host OrbStack operators находятся вне
trust boundary.

Read-only observer не выбирает процесс по substring: он перечисляет exact-name
`sing-box` candidates, записывает argv каждого, требует ровно один exact
managed argv, затем повторно доказывает PID/start/argv/executable/config в той
же стабильной process generation. Неоднозначность или restart делает snapshot
invalid.

Это узкий **synthetic Linux IPv4/netns implementation proof**, не
production/field/censor evidence. Он не доказывает IPv6, native Windows/macOS
TUN, fleet rollout или continuous host non-mutation.

## h2-chunk camouflage (legacy)

- Explicit no-TUN lab only; server requires
  `--development-user-allowlist --allow-insecure-lab-carriers`
- Client шлёт HTTP/2 preface + SETTINGS
- Server авто-детектит `PRI * HTTP/2`
- Весь протокол shadowpipe идёт внутри H2 DATA frames
- На wire — похоже на HTTPS/HTTP2, но это **не полноценный H2** (review H6: positive
  tell для stateful-парсера). Production/full-tunnel требует REALITY.

## Stream mux

`--mux-streams 24 --mux-chunk 4096` — IP packet fragmentation on the wire (not a TCP freeze countermeasure).

Volume guard (TCP reconnect every N bytes) is **off by default**. The per-5-tuple volume
freeze hypothesis did **not** reproduce in two manual RU→NL Chrome-TLS sessions
(20 MiB each, zero stalls, about 3–11 MiB/s) or the separate `planeb-01` raw-TCP run
(328.409 MB / about 313.2 MiB observed counters; 310 MiB nominal payload).
These are scoped, unsealed field observations, not a universal
negative. Rotating rebuilds the whole TLS+PQ session every `--guard-bytes`, which crushed
throughput by roughly three orders of magnitude in the observed run. Opt back in only for
a bounded experiment after the target stall reproduces. See `volume_guard.rs` and the
[claims ledger](docs/claims-ledger.md).

## Causal Carrier Plane — research MVP

The repository also contains a deliberately **offline, shadow-only** research
plane. It validates closed-schema local measurement traces, estimates
uncertainty from independent fixed-look windows, and reports which typed
carrier it *would* select. It has no route, DNS, TUN, socket-dial, or activation
handle.

```bash
cargo run -p shadowpipe-causal-replay -- \
  crates/shadowpipe-causal-replay/examples/scenario.example.json
```

The client can also emit an opt-in bounded terminal trace from its existing
no-TUN `--loadtest` path with `--measurement-json`, explicit
`--measurement-scope` / `--measurement-environment`, and cohort-binding
`--experiment-id` / `--artifact-id` values (32 lowercase hex digits each). A
pre-socket private same-directory temp reserves and preflights output; the final
JSON is file-fsynced and atomically hard-linked without overwrite (with mode
0600 and directory fsync on Unix). One 30-second dial lifecycle covers DNS, outer
TCP/QUIC/TLS/REALITY establishment, and inner AuthenticatedSession v3 authentication, so
failure and timeout attempts publish `Pending` `Dial + Close` traces instead of
vanishing. Raw exact timings and byte counts remain correlation-sensitive and
are not export-safe merely because the schema is closed. Every measurement
scope uses the same mandatory server-pin preflight; loopback/VM scope is not an
unpinned exception.

Start with [`docs/architecture-causal-carrier-plane.md`](docs/architecture-causal-carrier-plane.md),
[`docs/threat-model-2026.md`](docs/threat-model-2026.md), and
[`docs/claims-ledger.md`](docs/claims-ledger.md). The bounded novelty comparison
is in [`docs/related-work-matrix-2026.md`](docs/related-work-matrix-2026.md).
The implemented Phase-3 safety invariants and the sealed scoped Linux gates
are in [`docs/phase3-production-safety.md`](docs/phase3-production-safety.md).
The current scoped security/evidence review is
[`docs/security-audit-2026-07-16.md`](docs/security-audit-2026-07-16.md).
The superseded pre-Phase-3 dependency/ML-KEM snapshot remains at
[`docs/security-audit-2026-07-15.md`](docs/security-audit-2026-07-15.md).
Current-source platform evidence includes native Linux ARM64
[`20260716T122834Z-linux-arm64-current`](tests/portability/results/20260716T122834Z-linux-arm64-current/RESULT.md),
privileged synthetic Linux IPv4 OS-TUN
[`20260716T123535Z-91294-70zWb7`](tests/tun/results/20260716T123535Z-91294-70zWb7/RESULT.md)
and Windows ARM64 H2 no-TUN
[`20260716T125113Z-36840-dd0c2571`](tests/windows/results/20260716T125113Z-36840-dd0c2571/RESULT.md).
The Windows result does not exercise Wintun or mutate Windows routes, DNS,
firewall, or adapters. Older bundles remain historical diagnostics only.
The experiment manifests under
[`experiments/`](experiments/) are design drafts, not field evidence or frozen
preregistrations. The VM-only impairment harness is documented in
[`tests/netem/README.md`](tests/netem/README.md).

## Следующие продуктовые gates

- Android VpnService APK
- Multi-TCP (несколько сокетов)
- DNS-chunk camouflage
- Split-tunnel geosite RU
- IPv6, Windows Wintun и native macOS TUN leak/recovery cells
- Power-loss/torn-write durability and production fleet reboot/rollback drills
- Independent cryptographic/security review и field-tested fleet rotation/revocation

Operator-specific private research notes are intentionally not part of the
public source repository.

Upstream implementations are reference inputs only. Shadowpipe keeps its own
protocol, signed-policy, packet-tunnel and WAL architecture; license and
clean-room rules are defined in
[`docs/upstream-clean-room-policy.md`](docs/upstream-clean-room-policy.md).
The pinned sing-box/sing-tun/Xray platform synthesis, exact source references,
IPv6 staging decision and Linux/macOS/Windows adoption backlog are in
[`docs/upstream-platform-audit-2026-07-16.md`](docs/upstream-platform-audit-2026-07-16.md).
The bounded no-marketing comparison with current VLESS Encryption/REALITY,
Hysteria2 and AmneziaWG 2.0 is in
[`docs/protocol-comparison-2026-07-16.md`](docs/protocol-comparison-2026-07-16.md).
