# Hướng dẫn cài đặt Central (cho user)

> English: [user-install-guide.md](user-install-guide.md) — that file is canonical; this translation may lag.

> Máy: Ubuntu 24.04 amd64, Docker đã cài. Tổng thời gian khoảng 30 phút (phần build khoảng 10 phút).
> Lệnh ở bước 1 và 2 chạy từ thư mục repo `central` (bản checkout của bạn); bước 3 chạy ở console của máy; từ bước 4 trở đi dùng bản installer root-owned mà lần cài đầu để lại ở `/usr/lib/central/install/install.sh`.
> Installer chạy lại bao nhiêu lần cũng an toàn: bước nào đã xong sẽ báo `OK ... (already present)`. Nó không bao giờ ghi đè một file cấu hình hay unit khác với bản nó sẽ ghi (nó in diff và dừng). Riêng `--from-source` thay các binary Central trong `/usr/lib/central` và in ra từng binary được thay.

## 0. Chuẩn bị máy (một lần, khoảng 10 phút)

1. Docker Engine + compose plugin, bật containerd image store: thêm `"features": {"containerd-snapshotter": true}` vào `/etc/docker/daemon.json`, rồi `sudo systemctl restart docker`.
2. User của bạn **không** được nằm trong group `docker` (group đó tương đương root): `sudo gpasswd -d "$USER" docker`, rồi đăng xuất và đăng nhập lại.
3. Công cụ build và tải: `sudo apt-get install gcc make libpam0g-dev curl gnupg`, và Go đúng bản trong `go.mod` (1.26.6) tải từ [go.dev](https://go.dev/dl/). `gnupg` cần khi installer phải tải khóa apt của PostgreSQL (nó kiểm tra fingerprint khóa bằng `gpg` trước khi cài).
4. Ổ chứa `/var/lib` còn trống ít nhất 40 GiB; RAM khuyến nghị 8 GiB.

## 1. Xem trước (không cần sudo, khoảng 1 phút)

```bash
packaging/install/install.sh --dry-run --operator-user "$USER" --from-source "$PWD" --yes
```

Lệnh này không đổi gì trên máy: nó kiểm tra điều kiện (preflight) rồi in mọi việc sẽ làm dưới dạng `would ...`. Nếu một dòng preflight báo lỗi, sửa theo dòng `fix:` ngay bên dưới (bảng cuối trang).

Mặc định là production admission (installer tự cài bundle v2 đi kèm sau genesis). `--dev-admission` giờ chỉ là công tắc phát triển, khi cần mới thêm (xem "Trạng thái hiện tại"): truyền đúng bộ cờ đó ở mọi lần chạy, vì đổi cờ giữa hai lần chạy làm `/etc/central/helper.env` khác đi và installer dừng lại.

## 2. Cài (cần sudo, khoảng 15 phút)

```bash
sudo packaging/install/install.sh --from-source "$PWD" --yes
```

Installer làm 8 bước: ghim `postgresql-client-16` bản 16.14 (và `apt-mark hold`), tạo user `central_runtime` (501) và `central_migrate` (986), build các binary **bằng user của bạn** (không phải root) rồi chép vào `/usr/lib/central` cùng bản sao installer ở `/usr/lib/central/install`, ghi PAM service `/etc/pam.d/central-helper`, cài các systemd unit, ghi manifest `/var/lib/central-install/manifest.json` (ghi lại sau từng mục, nên lần chạy dừng giữa chừng vẫn có bản ghi đúng), và cuối cùng in một khung **NEXT** hướng dẫn bước 3. Nhật ký: `/var/log/central-install.log` (quyền 0600, root).

`--from-source` coi bản checkout như dữ liệu đầu vào ngang quyền root: chỉ dùng trên máy phát triển, và installer từ chối chạy khi harness launcher đang bật.

**Nâng cấp** luôn chạy script của checkout mới, không phải bản đã cài: `sudo <checkout>/packaging/install/install.sh --from-source <checkout> --yes` (với harness đã dừng). Nó build lại binary và chép lại script cùng các unit vào `/usr/lib/central/install`, in ra diff. Bản `/usr/lib/central/install/install.sh` giữ script và unit cũ của nó, nên nó từ chối (exit 3) `--from-source` một checkout có script hoặc unit khác nó, và in đúng lệnh trên. Chạy không có `--from-source` thì không bao giờ build lại hay thay bản sao.

## 3. Tạo instance tại console của máy (không qua SSH, khoảng 3 phút)

1. Ngồi trước chính máy đó (console text như Ctrl+Alt+F3, hoặc cửa sổ console của VM) và đăng nhập bằng user của bạn.
2. **Tắt bộ gõ** (ví dụ bộ gõ tiếng Việt), dùng bàn phím thường.
3. Chạy `central local init`. Nhập mật khẩu, rồi gõ lại câu xác nhận đúng như dòng hiện trên màn hình (không có dấu ngoặc), trong số giây mà dòng nhắc ghi.
4. Gõ sai lần đầu: màn hình báo `That did not match. Turn off any input method and type it again.` và cho gõ lại một lần với cùng mã. Sai lần hai: lệnh kết thúc với exit 7, không tạo gì cả; tắt bộ gõ rồi chạy lại `central local init`.

## 3b. Tạo instance không cần ngồi trước máy (grant mode, khoảng 2 phút)

Khi không ai ở console của máy, user root (qua SSH) cho phép trước một lần tạo instance, rồi `central local init` chạy qua SSH mà không hỏi gì:

```bash
sudo central grant issue --kind init --ttl 10m
# {"kind":"init","nonce":"...","issued_at":"...","expires_at":"..."}

sudo -u <operator> central local init
# {"schema_version":"central.local-result/v1","command_id":"local.init","exit_code":0,...}
```

Luật: cùng lúc chỉ có một grant dùng được (lệnh issue lần hai bị từ chối với `GRANT_PENDING`, trừ khi thêm `--replace`); TTL mặc định và tối đa 15 phút; mỗi grant dùng một lần và gắn với đúng lần boot hiện tại; không có grant thì nghi thức console ở bước 3 chạy như cũ. Instance tạo ra đã ở grant ceremony mode ngay từ đầu (`central grant issue --kind lifecycle ...` dùng được luôn, không cần `central grant mode grant`).

## 4. Chạy lại installer (khoảng 1 phút)

```bash
sudo /usr/lib/central/install/install.sh --yes
```

Lần này installer bật broker và in mục **after genesis**: những gì máy còn thiếu cho `local prepare`, `local up`, `migrate up`. Dùng đúng bộ cờ của bước 2. Lần chạy lại không có `--from-source` thì không build lại binary.

## 5. Kiểm tra (khoảng 1 phút)

```bash
sudo /usr/lib/central/install/install.sh --verify
```

Mỗi dòng là `OK` hoặc `FAIL` kèm cách sửa; `SKIP` cho `migrate status` khi instance chưa chạy. Exit 0 nghĩa là mọi kiểm tra đều qua. `--verify` chỉ đọc, không đổi gì.

## 6. Dùng bản phát hành có chữ ký (maintainer xuất, user nhập, khoảng 5 phút)

Máy user cuối không giữ private key nên không tự build và ký được: maintainer build một lần rồi xuất thành một thư mục bản phát hành, user nhập vào máy mình. Hai lệnh dưới đều cần dấu `=` (`--export-release=<thư mục>`, `--from-release=<thư mục>`); viết cách ra (`--from-release /tmp/...`) thì cờ bị bỏ qua và lệnh chạy như `prepare` trơn.

1. Maintainer, trên máy giữ key (đã `up` ít nhất một lần để có infra image): `central local prepare --export-release=/tmp/central-release-a1` → exit 0, thư mục 7 file (`release.json`, `minio/` gồm image/comparison/3 attestation, `infra/image.tar`).
2. Maintainer nén và gửi: `tar czf central-release-a1.tar.gz -C /tmp central-release-a1`, đọc `sha256sum`, gửi file cùng hash cho user qua kênh tin cậy.
3. User, trên máy nhận: kiểm tra hash (`sha256sum` phải khớp từng byte), rồi giải nén (`tar xzf central-release-a1.tar.gz -C /tmp`).
4. User nhập (cần grant, chạy bằng operator user như mọi lệnh local): root chạy `sudo central grant issue --kind prepare --ttl 1h`, rồi `sudo -u <operator> central local prepare --from-release=/tmp/central-release-a1` → exit 0. Bản nhập không tải cũng không build gì nên không cần mạng.
5. User chạy tiếp như thường: `local up`, `migrate up`, `local up` (mỗi lệnh `migrate` tốn một grant `--kind lifecycle` riêng).

Luật: máy không key mà chạy `prepare` trơn thì bị `PREPARE_UNAVAILABLE` ngay và không ghi nhật ký; bản phát hành bị sửa dù một byte thì bị `RELEASE_UNTRUSTED` và không ghi gì vào store.

## Gỡ cài đặt

```bash
sudo /usr/lib/central/install/install.sh --uninstall
```

Chỉ gỡ những gì có trong manifest (unit, binary, file cấu hình, user mà installer đã tạo). Dữ liệu (`/var/lib/central-state`, `/var/lib/central-protected`) được **giữ lại**; muốn xóa luôn thì thêm `--purge-data` (phải gõ đúng instance id, từng byte) hoặc `--yes --purge-data`. Với `--purge-data`, installer dừng container của instance trước; nếu `docker compose down` lỗi, hoặc Docker daemon không trả lời (đã dừng hay bị treo), thì dữ liệu **không** bị xóa, lệnh in `NOT REMOVED`, liệt kê container còn lại và kết thúc với exit 1. `/etc/central` được giữ nếu còn file bạn tự thêm vào (ví dụ `harness-launcher.conf`). `postgresql-client-16` và nguồn apt của PostgreSQL cũng được giữ; lệnh in cách gỡ tay.

Sau khi gỡ xong, installer kiểm tra lại từng mục. Nếu còn sót (unit vẫn đang chạy, container còn lại, một file không xóa được), lệnh liệt kê phần còn lại, **giữ manifest**, kết thúc với exit 1: xử lý phần còn lại rồi chạy lại đúng lệnh trên. Không có manifest, hoặc manifest mà installer không đọc được chính xác, thì lệnh từ chối (exit 3) và không đổi gì.

## Trạng thái hiện tại (đọc để khỏi tưởng bở)

- Chạy được: preflight, cài host, tạo instance ở console, `--verify`, `--uninstall`, mọi lệnh `central` giờ trả exit code đúng với `exit_code` trong JSON, nhập bản phát hành có chữ ký của maintainer (mục 6) rồi `up`/`migrate` như thường, và production admission với advisory bundle có chữ ký v2 (sub-project A2 xong: installer tự cài bundle đi kèm sau genesis, `--verify` báo khi bundle thiếu, hết hạn, hay còn dưới 30 ngày).
- `--dev-admission` lại chỉ là công tắc phát triển: máy đã có bundle v2 thì `local prepare`/`up` chạy production admission mà không cần nó, và nó không bao giờ là bằng chứng nghiệm thu.
- Chưa chạy được trên máy của user cuối:
  1. `local prepare` tự build và ký vẫn cần private key của maintainer; máy user nhập bản phát hành (mục 6) thay vì tự build. Đóng gói và phân phối bản phát hành (tarball, checksum có chữ ký, registry) là sub-project A.
  2. Tạo instance không cần người ở console chạy được rồi (mục 3b: root cấp `central grant issue --kind init` trước, rồi `local init` qua SSH); installer tự làm việc này (`--grant-mode`) vẫn chờ sub-project D.

## Gặp lỗi thường gặp

Mỗi lỗi preflight in một dòng nguyên nhân, một dòng `fix:` và `nothing was changed` (máy chưa bị đổi gì). Exit 3 là điều kiện chưa đủ, exit 4 là thiếu chỗ trống, exit 2 là sai tham số.

| Installer báo | Cách sửa |
|---|---|
| `this host is ... ; Central installs on Ubuntu 24.04 amd64 only` | Cài Ubuntu 24.04 LTS bản amd64. |
| `install.sh must run as root` | Chạy lại với `sudo` (lần cài đầu và mỗi lần nâng cấp `sudo <checkout>/packaging/install/install.sh --from-source <checkout> ...`; các lần chạy lại khác `sudo /usr/lib/central/install/install.sh ...`). |
| `no operator: run through sudo ...` / `operator ... does not exist` / `the operator must not be root` | Chạy qua `sudo` từ chính user của bạn, hoặc thêm `--operator-user <login>` (không dùng `root`, `central_runtime`, `central_migrate`). |
| `--operator-user must be a login name` | Truyền đúng tên đăng nhập (chữ, số, `_`, `.`, `-`; tối đa 32 ký tự), không phải tên hiển thị hay uid. |
| `the operator must be a login user: ... has uid ..., below UID_MIN ...` | User đó là user hệ thống (uid nhỏ hơn `UID_MIN` trong `/etc/login.defs`). Truyền user đăng nhập của chính bạn với `--operator-user`. |
| `systemd is not running as the init system` | Khởi động máy bằng systemd (mặc định của Ubuntu). |
| `Docker is not installed` / `Docker is installed but its daemon does not answer` | Cài Docker Engine; hoặc `sudo systemctl enable --now docker` rồi kiểm tra `sudo docker info`. |
| `the Docker compose plugin is missing` | `sudo apt-get install docker-compose-plugin` |
| `Docker does not use the containerd image store` | Thêm `"features": {"containerd-snapshotter": true}` vào `/etc/docker/daemon.json`, rồi `sudo systemctl restart docker`. |
| `operator ... is in the docker group` / `... is in the group central_runtime` | `sudo gpasswd -d <user> docker` (hoặc group được nêu), đăng xuất rồi đăng nhập lại. |
| `... GiB free on the /var/lib filesystem; genesis needs 40 GiB` (exit 4) | Giải phóng chỗ trên ổ chứa `/var/lib` (`df -h /var/lib`). |
| `uid 501 belongs to ...` / `gid 986 belongs to group ...` / `user central_runtime exists with uid ...` | Uid/gid đó đang thuộc user khác (thường gặp: `systemd-oom` giữ 986), hoặc user `central_*` cũ có id khác. Chuyển user kia sang id khác (`sudo usermod -u`, `sudo groupmod -g`), hoặc cài trên máy còn trống uid/gid đó. Đổi uid của Central phức tạp hơn nhiều (nhiều chỗ kiểm tra cứng). |
| `Central binaries missing from /usr/lib/central: ...` | Build từ checkout bằng script của chính checkout: `sudo <checkout>/packaging/install/install.sh --from-source <checkout> ...`. |
| `this is the installed copy /usr/lib/central/install/install.sh, and the checkout's ... differ from it` | Nâng cấp bằng script của checkout, đúng lệnh ở dòng `fix:` (`sudo <checkout>/packaging/install/install.sh --from-source <checkout> ...`), với harness launcher đã dừng. |
| `--from-source ... is not a Central checkout` / `--from-source must be an absolute path to an existing directory` | Truyền đường dẫn tuyệt đối tới gốc repo `central` (thư mục có `go.mod`). |
| `the agent harness launcher is active` / `install.sh runs from ..., not from the root-owned /usr/lib/central/install/install.sh` | Chạy bằng bản root-owned (`sudo /usr/lib/central/install/install.sh ...`), hoặc `sudo systemctl stop central-harness-launcher.socket central-harness-launcher.service` rồi chạy lại. |
| `the installer copy cannot be trusted ...` | File hoặc thư mục dưới `/usr/lib/central/install` không còn root-owned hoặc ghi được bởi người khác: làm theo dòng `fix:` (chown/chmod), rồi chạy lại. |
| `<thư mục> is owned by uid N, not root; install.sh puts root's files only in root-owned directories nobody else can write` / `<thư mục> has mode NNN: its group or others can write it; install.sh puts root's files only in root-owned directories nobody else can write` / `<thư mục> is a symlink` | Một thư mục installer ghi vào (`/usr/lib/central`, `/etc/central`, `/etc/systemd/system/central-helper.socket.d`, `/var/lib/central-install`, ...) không phải của root, ghi được bởi group/người khác, hoặc là symlink. Tìm xem ai đổi nó, rồi `sudo chown root:root <thư mục> && sudo chmod go-w <thư mục>` (hoặc dời nó đi), chạy lại. |
| `no go in ...'s login PATH` / `... the checkout needs Go 1.26.6` | Cài Go 1.26.6, hoặc thêm `--go /đường/dẫn/tới/go`. Installer build với `GOTOOLCHAIN=local`, không tự tải toolchain. |
| `gcc is missing` / `make is missing` / `libpam0g-dev is missing` | `sudo apt-get install gcc make libpam0g-dev` |
| `curl is missing` / `gpg is missing` | `sudo apt-get install curl gnupg` |
| `the PostgreSQL apt repository ... is not reachable` | Kiểm tra mạng hoặc proxy tới `apt.postgresql.org`, rồi chạy lại. |
| `postgresql-client-16 ... is installed, newer than the 16.14... Central pins` | Installer không tự hạ phiên bản. Nếu không gì khác cần bản mới: `sudo apt-get install --allow-downgrades postgresql-client-16=16.14-1.pgdg24.04+1`, rồi chạy lại. |
| `/usr/local/bin/central exists and is not a link to /usr/lib/central/central` | Một file hoặc link khác đang chiếm `/usr/local/bin/central`: dời nó đi (`sudo mv /usr/local/bin/central /usr/local/bin/central.old`) rồi chạy lại. |
| `... exists and differs from what install.sh would write` (exit 3) | Installer không ghi đè file người khác đã sửa. Đọc diff in ra, rồi dời file đó đi (`sudo mv <file> <file>.old`) và chạy lại. Với `/etc/central/helper.env`, đây là cách đổi operator hoặc chế độ admission. |
| `/var/lib/central-install/manifest.json is not understood (...)` (exit 3) | Manifest bị sửa tay hoặc hỏng. Installer không ghi lại hay làm theo một manifest nó không đọc chính xác: xem bằng `sudo cat -A`, đưa về dạng một mục mỗi dòng như installer ghi, rồi chạy lại. |
| `/var/log/central-install.log is a symlink or not a regular file` | Tìm xem ai tạo nó, dời đi (`sudo mv /var/log/central-install.log /var/log/central-install.log.suspect`), chạy lại. |
| `central local init` báo `AUTHORITY_DENIED` với gợi ý "not SSH" | Lệnh phải chạy ở console thật của máy, không qua SSH. |
| `central local init`: `the typed phrase did not match the one shown, twice` | Tắt bộ gõ, chạy lại `central local init`, gõ câu xác nhận đúng như hiện trên màn hình. |
| `--uninstall` kết thúc exit 1 và liệt kê các mục còn lại | Xử lý từng mục (ví dụ `sudo systemctl stop <unit>`, `docker compose down` của instance, `sudo systemctl start docker` khi báo `the Docker daemon does not answer`, hoặc `sudo chattr -i <file>`), rồi chạy lại `sudo /usr/lib/central/install/install.sh --uninstall`. |
| `FAIL  no advisory bundle installed` (`--verify`) | Chạy lại installer với đúng bộ cờ cũ (`sudo /usr/lib/central/install/install.sh ...`): nó cài bundle đi kèm sau genesis. |
| `FAIL  the advisory bundle expired ...` (`--verify`) | Bundle đã hết hạn, production admission từ chối mọi thứ: lấy bundle của bản phát hành hiện tại rồi chạy lại installer. |

## Cài từ bản phát hành (không cần checkout)

Bản `install.sh` đi kèm mỗi release tự tải tarball đúng phiên bản của nó (mặc định từ trang GitHub releases) và kiểm tra chữ ký (`ssh-keygen`), sha256 rồi mã phiên bản trước khi cài binary có sẵn — không cần Go, gcc hay checkout. `--from-source` chỉ dành cho developer build từ source.

Trước khi `sudo bash`, kiểm tra key (không cần sudo, khoảng 10 giây):

```bash
bash install.sh --show-release-key
```

So fingerprint `SHA256:...` in ra với fingerprint trong release notes: chỉ chạy tiếp khi hai bên khớp nhau.
