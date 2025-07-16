# load_domain_from_pcap_to_mysql

tên domain xuất hiện ở QUIC và TLS nên trích từ 2 cái đấy, TLS thì dễ rồi nhưng QUIC thì domain nó ko nằm ở ngay phần info (SNI=...) như TLS nên mới khoai tí, mãi mới ấy được:'

ý tưởng là dùng tshark đọc file pcap, trích các tên miền từ QUIC và TLS, lưu vào dataset, xong rồi từ dataset ném vào database (đang dùng mysql)
(thử test file pcap 1gb mất ~18s)

1. file txt để ghi những domain có ích (domain giữ lại, để loại bỏ các domain rác, quảng cáo, domain của google trong quá trình cature wireshark)
2. file py, nhập input là file txt, file pcap, tên database, tên table
   (còn tên host, user, password ít khi đổi nên để luôn trong code :v )
   sau khi chạy code có xuất ra 1 file dataset chứa tất cả các tên miền (kể cả miền rác và có ích) ra thư mục chứa file pcap
3. à cái table trong mysql đang để như này:
CREATE TABLE logs3 (
    id INT AUTO_INCREMENT PRIMARY KEY,
    frame_number INT,
    time_full DATETIME(6),
    src_ip VARCHAR(45),
    src_port INT,
    dst_ip VARCHAR(45),
    dst_port INT,
    protocol VARCHAR(10),
    length INT,
    domain VARCHAR(255)
);
