# Tài liệu kỹ thuật: Tạo user, phân quyền home và cấu hình SSH/SFTP chroot trên Rocky Linux

## Mục đích

Tài liệu này tổng hợp quy trình tạo user có home directory riêng trên Rocky Linux, đặt quyền truy cập phù hợp cho thư mục home, và cấu hình SSH/SFTP để user chỉ hoạt động trong phạm vi thư mục được chỉ định.[cite:39][cite:49][cite:51]

Mục tiêu chính là phân biệt rõ hai mô hình vận hành: SSH shell thông thường và SFTP-only có chroot, vì hai mô hình này có mức độ cô lập và cách cấu hình khác nhau.[cite:49][cite:75][cite:85]

## Tạo user kèm home directory

Trên Rocky Linux, có thể tạo user và home directory cùng lúc bằng lệnh `useradd -m <username>`; tùy chọn `-m` yêu cầu hệ thống tự tạo thư mục home nếu chưa tồn tại.[cite:39] Nếu cần chỉ định shell, có thể dùng thêm `-s`, ví dụ `/bin/bash` cho shell thông thường hoặc `/sbin/nologin` cho tài khoản chỉ dùng SFTP.[cite:39][cite:40]

Ví dụ tạo user shell thông thường:

```bash
useradd -m -s /bin/bash backup1
passwd backup1
```

Ví dụ tạo user chỉ phục vụ SFTP:

```bash
useradd -m -s /sbin/nologin backup1
passwd backup1
```

Nếu cần đặt home ở vị trí khác ngoài `/home/<username>`, có thể dùng thêm `-d` kết hợp với `-m` để vừa chỉ định vừa tạo thư mục đó.[cite:39][cite:40]

## Phân quyền home directory

Để giới hạn user chỉ có quyền đầy đủ trong thư mục home của chính họ, cần đặt owner đúng và đặt quyền truy cập thư mục home về `700`.[cite:12] Quyền `700` cho phép chủ sở hữu đọc, ghi và truy cập thư mục, đồng thời chặn các user khác truy cập vào home đó.[cite:12]

Ví dụ:

```bash
chown -R backup1:backup1 /home/backup1
chmod 700 /home/backup1
```

Cách làm này ngăn user khác truy cập vào home của `backup1`, nhưng không phải là cơ chế cô lập hoàn toàn khỏi toàn bộ filesystem khi user vẫn có shell chuẩn.[cite:12][cite:20]

## Giới hạn thực tế của SSH shell thông thường

Nếu user được cấp shell chuẩn như `/bin/bash`, họ thường không thể ghi vào các thư mục hệ thống như `/etc`, `/root` hoặc `/var` vì các thư mục này thuộc root và không cấp quyền write cho user thường.[cite:12] Tuy nhiên, user vẫn có thể nhìn thấy hoặc đọc một số thư mục hệ thống được cấp quyền public, vì permission Unix thông thường không tạo ra sandbox hoàn chỉnh.[cite:12][cite:20]

Do đó, nếu yêu cầu là user chỉ được làm việc bên trong một thư mục riêng và không đi ra ngoài được, chỉ dùng `chmod` và `chown` là chưa đủ; cần dùng chroot, jail hoặc container.[cite:20][cite:75]

## Mô hình SSH shell thông thường

Mô hình này phù hợp khi user cần đăng nhập SSH đầy đủ để chạy lệnh, thao tác file trong home, nhưng không cần mức cô lập filesystem tuyệt đối.[cite:49] Trong trường hợp này, chỉ cần tạo user, đặt quyền home `700`, và có thể giới hạn user nào được SSH bằng `AllowUsers` trong `sshd_config`.[cite:5][cite:49]

Ví dụ cấu hình cơ bản:

```bash
useradd -m -s /bin/bash backup1
passwd backup1
chown -R backup1:backup1 /home/backup1
chmod 700 /home/backup1
mkdir -p /home/backup1/.ssh
chmod 700 /home/backup1/.ssh
touch /home/backup1/.ssh/authorized_keys
chmod 600 /home/backup1/.ssh/authorized_keys
chown -R backup1:backup1 /home/backup1/.ssh
restorecon -Rv /home/backup1
```

Quyền `700` cho thư mục `.ssh` và `600` cho file `authorized_keys` là thiết lập được khuyến nghị khi dùng SSH key với OpenSSH.[cite:45][cite:46]

Ví dụ giới hạn SSH cho đúng user này trong `/etc/ssh/sshd_config`:

```conf
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication yes
AllowUsers backup1
```

Sau khi thay đổi cấu hình SSH, nên kiểm tra bằng `sshd -t` trước khi restart dịch vụ để tránh lỗi cấu hình làm mất truy cập từ xa.[cite:49][cite:88]

## Mô hình SFTP-only với chroot

Nếu yêu cầu là user chỉ upload/download file trong thư mục riêng và không được thoát ra ngoài, mô hình phù hợp là dùng `ForceCommand internal-sftp` kết hợp `ChrootDirectory`.[cite:51][cite:75][cite:85] Đây là cấu hình chuyên dùng cho tài khoản SFTP-only và khác với SSH shell thông thường.[cite:75][cite:77]

Trong mô hình chroot, thư mục gốc của jail phải thuộc `root` và không được writable bởi user bị nhốt, nếu không OpenSSH sẽ từ chối đăng nhập.[cite:75][cite:78] Vì vậy, không nên cho user ghi trực tiếp vào chính thư mục chroot mà nên tạo một thư mục con writable bên trong.[cite:75]

Ví dụ tạo cấu trúc thư mục chroot:

```bash
useradd -m -s /sbin/nologin backup1
passwd backup1

mkdir -p /sftp/backup1/home
chown root:root /sftp/backup1
chmod 755 /sftp/backup1

chown backup1:backup1 /sftp/backup1/home
chmod 700 /sftp/backup1/home
```

Trong cấu trúc này, `/sftp/backup1` là thư mục chroot thuộc root, còn `/sftp/backup1/home` là nơi user được phép ghi dữ liệu.[cite:75][cite:78]

## Ý nghĩa của `usermod -d /home backup1`

Lệnh `usermod -d /home backup1` đổi home directory logic của user `backup1` thành `/home` trong thông tin account.[cite:65][cite:68] Trong mô hình chroot với `ChrootDirectory /sftp/backup1`, khi user đăng nhập, `/sftp/backup1` sẽ trở thành `/` theo góc nhìn của user, nên home `/home` sẽ tương ứng với thư mục thật `/sftp/backup1/home` trên host.[cite:68][cite:72]

Ví dụ:

```bash
usermod -d /home backup1
```

Lệnh này không tự di chuyển dữ liệu nếu không dùng thêm `-m`; trong case chroot, mục đích của nó là điều chỉnh điểm rơi sau khi đăng nhập chứ không phải move thư mục cũ.[cite:65][cite:66][cite:74]

## Cấu hình `Subsystem sftp internal-sftp`

Có thể thay dòng `Subsystem sftp /usr/libexec/openssh/sftp-server` bằng `Subsystem sftp internal-sftp` trong `sshd_config` khi triển khai mô hình SFTP-only.[cite:85][cite:88] `internal-sftp` là implementation chạy bên trong tiến trình `sshd`, phù hợp hơn với chroot vì không phụ thuộc vào binary SFTP server bên ngoài.[cite:85]

Ví dụ cấu hình nên dùng:

```conf
Subsystem sftp internal-sftp
```

Chỉ nên có một dòng `Subsystem sftp ...` có hiệu lực trong `sshd_config`, và luôn nên kiểm tra cú pháp bằng `sshd -t` trước khi restart dịch vụ.[cite:86][cite:88]

## Root có SSH bình thường khi dùng `internal-sftp` không

Việc đổi sang `Subsystem sftp internal-sftp` không tự động làm root mất SSH shell bình thường, vì dòng này chỉ áp dụng cho SFTP subsystem.[cite:85][cite:92] Root chỉ bị ảnh hưởng nếu có thêm cấu hình như `PermitRootLogin no`, hoặc có `Match User root` hay `ForceCommand` áp riêng cho root.[cite:95]

Nếu block `Match User` chỉ áp cho `backup1`, thì root không thuộc phạm vi match đó và vẫn SSH shell bình thường, miễn là `PermitRootLogin` cho phép.[cite:94][cite:96]

## Cấu hình `Match User` và thời điểm áp dụng

Block `Match User backup1` không bắt buộc phải khai báo trước khi chạy `usermod -d /home backup1`, vì `usermod` chỉ sửa thông tin account của user.[cite:68] Tuy nhiên, để user thực sự bị ép vào SFTP-only và chroot, block `Match User` phải được thêm vào `sshd_config` trước khi đăng nhập thử.[cite:75][cite:77]

Ví dụ cấu hình:

```conf
Subsystem sftp internal-sftp

Match User backup1
    ChrootDirectory /sftp/backup1
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
```

Thứ tự an toàn là tạo user, tạo cấu trúc thư mục chroot, phân quyền đúng, điều chỉnh home logic bằng `usermod -d /home`, sau đó mới cập nhật `sshd_config`, kiểm tra với `sshd -t` và restart `sshd`.[cite:75][cite:80]

## Ý nghĩa của `restorecon -Rv /sftp`

Lệnh `restorecon -Rv /sftp` dùng để khôi phục SELinux context mặc định cho thư mục `/sftp` và toàn bộ nội dung bên trong theo policy của hệ thống.[cite:55][cite:56] Trên Rocky Linux, bước này hữu ích sau khi tạo thư mục SFTP/SSH bằng tay vì SELinux có thể chặn truy cập dù owner và permission Unix đã đúng.[cite:58][cite:61]

Trong lệnh này, `-R` là áp dụng đệ quy cho toàn bộ thư mục con, còn `-v` là hiển thị chi tiết các thay đổi.[cite:56][cite:59] Lệnh này không thay đổi owner, group hay mode như `chown` và `chmod`, mà chỉ sửa nhãn bảo mật SELinux.[cite:55][cite:60][cite:61]

Có thể xem trước thay đổi mà không áp dụng bằng:

```bash
restorecon -Rnv /sftp
```

## Quy trình triển khai khuyến nghị

### Trường hợp 1: User SSH shell thông thường

```bash
useradd -m -s /bin/bash backup1
passwd backup1
chown -R backup1:backup1 /home/backup1
chmod 700 /home/backup1
mkdir -p /home/backup1/.ssh
chmod 700 /home/backup1/.ssh
touch /home/backup1/.ssh/authorized_keys
chmod 600 /home/backup1/.ssh/authorized_keys
chown -R backup1:backup1 /home/backup1/.ssh
restorecon -Rv /home/backup1
sshd -t && systemctl restart sshd
```

Mô hình này cho phép user SSH shell như bình thường, chỉ giới hạn quyền ghi bằng permission Unix và không cô lập hoàn toàn khỏi toàn bộ filesystem.[cite:12][cite:49]

### Trường hợp 2: User SFTP-only bị nhốt trong thư mục riêng

```bash
useradd -m -s /sbin/nologin backup1
passwd backup1
mkdir -p /sftp/backup1/home
chown root:root /sftp/backup1
chmod 755 /sftp/backup1
chown backup1:backup1 /sftp/backup1/home
chmod 700 /sftp/backup1/home
usermod -d /home backup1
restorecon -Rv /sftp
sshd -t && systemctl restart sshd
```

Đồng thời cần thêm block sau vào `/etc/ssh/sshd_config`:[cite:75][cite:85]

```conf
Subsystem sftp internal-sftp

Match User backup1
    ChrootDirectory /sftp/backup1
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
```

Mô hình này phù hợp khi mục tiêu là chỉ cho phép upload/download file trong thư mục riêng và không cho user thoát ra ngoài bằng shell.[cite:51][cite:75][cite:85]

## So sánh hai mô hình

| Tiêu chí | SSH shell thường | SFTP-only chroot |
|---------|------------------|------------------|
| Shell bash | Có thể có [cite:39][cite:49] | Không, bị ép `internal-sftp` [cite:75][cite:85] |
| Ghi dữ liệu trong home | Có [cite:12] | Có, trong thư mục writable bên trong jail [cite:75][cite:78] |
| Thấy filesystem hệ thống | Có thể thấy một phần thư mục public [cite:12][cite:20] | Không thấy ngoài jail [cite:75][cite:77] |
| Phù hợp upload/download file | Tạm được [cite:49] | Phù hợp nhất [cite:51][cite:75] |
| Mức cô lập | Thấp hơn [cite:20] | Cao hơn [cite:75][cite:85] |

## Khuyến nghị triển khai

Nếu user cần chạy lệnh quản trị hoặc thao tác shell, nên dùng SSH shell thông thường với home `700`, không thêm user vào các group đặc quyền không cần thiết, và cân nhắc giới hạn user bằng `AllowUsers`.[cite:12][cite:49] Nếu user chỉ cần truyền file, nên dùng SFTP-only với `ChrootDirectory` và `internal-sftp`, vì đây là mô hình sát với yêu cầu “chỉ được vào thư mục riêng” hơn permission Unix thông thường.[cite:51][cite:75][cite:85]

Trên Rocky Linux có SELinux, vì vậy sau khi tạo cây thư mục cho SSH hoặc SFTP bằng tay, nên chạy `restorecon` để đồng bộ lại security context và giảm nguy cơ lỗi truy cập khó debug.[cite:55][cite:58]
