# Agent brief: one-click install cho Central (paste nguyên văn cho AI agent)

## Bối cảnh

Central là workspace AI local-first, durable (Go, PostgreSQL, MinIO, Docker Compose).
Hôm nay user thường KHÔNG thể cài mượt: muốn chạy phải đọc source, chạy script
`scripts/sc-g3-reference-host-bringup.sh` dành cho reference-host, tự hiểu 2 chế độ
ceremony (`grant` unattended / `physical_tty` console thật), tự xử lỗi (uid chiếm,
thiếu tag pam, sai bản psql). README đã có quickstart 5 lệnh nhưng vẫn là
operator-style, chưa phải install UX.

## Mục tiêu

Một user Ubuntu 24.04 sạch, có sudo + mạng, cài được Central đang chạy bằng
**một lệnh duy nhất**, ví dụ:

```bash
curl -fsSL <url>/install.sh | sudo bash
```

hoặc tương đương (`central-install` one-shot). Sau đó `central local status`
báo instance hoạt động, không cần đọc source.

## Ràng buộc cứng (vi phạm là fail)

1. Đọc `AGENTS.md`, `README.md`, `scripts/sc-g3-reference-host-bringup.sh`,
   `docs/operations/user-install-guide.md` trước khi làm.
2. KHÔNG làm yếu security model: giữ phân tách uid (operator ≠ root ≠ daemon),
   operator không có quyền Docker socket, giữ nguyên ngữ nghĩa ceremony
   (grant-unattended phải đánh dấu instance `ceremony_mode: grant` như hiện tại;
   không bao giờ tự động vượt qua physical-console ceremony rồi ghi nhận như
   user đã xác nhận).
3. KHÔNG đổi digest pin, wire format, hay quyết định của ADR đã Accepted để
   "cho dễ cài". Cái gì cần nới phải viết ADR Proposed, không tự ý.
4. Idempotent: chạy installer 2 lần không hỏng instance đang chạy.
5. Mọi bước phá hủy (xóa instance cũ, ghi đè config) phải hỏi xác nhận rõ ràng,
   trừ khi có flag `--yes` tường minh.
6. Không commit secret, token, `.env`. Mọi file mới phải `gofmt` sạch (nếu là Go).

## Tiêu chí chấp nhận

- [ ] Ubuntu 24.04 VM sạch + Docker + sudo: một lệnh → `central local status` xanh.
- [ ] Lỗi thường gặp (thiếu Docker, uid 501/986 bị chiếm, sai bản psql, thiếu RAM/disk)
      báo bằng tiếng người + cách sửa, không stack trace trần.
- [ ] Có lệnh verify sau cài (`central doctor` hoặc `install.sh --verify`).
- [ ] Có `--uninstall` dọn sạch những gì installer tạo (trừ dữ liệu user, phải hỏi).
- [ ] README + `docs/operations/user-install-guide.md` cập nhật theo installer mới;
      xóa quickstart cũ nếu đã lỗi thời.
- [ ] Ghi lại quyết định + gap còn lại vào `tasks/` theo format SC-DEF hiện có.

## Không làm

- Không build Online Mode / Server — scope là local-first như hiện tại.
- Không refactor ngoài vùng installer trừ khi bắt buộc để installer chạy được.
- Không tự chạy installer với sudo trong môi trường dev của mình để "test cho nhanh"
  nếu việc đó đụng production paths của máy dev — dùng VM/container sạch, hoặc
  trình bày kế hoạch test trước.

## Cách bắt đầu (gợi ý, không bắt buộc)

1. Chạy thử bringup script hiện tại trên VM sạch, ghi lại mọi chỗ vấp.
2. Bọc nó thành installer một lệnh + preflight checks + thông báo tiến trình rõ ràng.
3. Dry-run mode (`--dry-run`) in ra mọi việc sẽ làm trước khi đụng hệ thống.
