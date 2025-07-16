import csv
import mysql.connector
import subprocess
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import time

start_time = None
timer_running = False

def update_timer():
    if timer_running:
        elapsed = int(time.time() - start_time)
        timer_label.config(text=f"🕒 Đang xử lý... {elapsed} giây")
        root.after(1000, update_timer)

def is_allowed(domain, allowed_domains):
    return any(allowed in domain for allowed in allowed_domains)

def load_allowed_domains(file_path):
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        messagebox.showerror("Lỗi khi đọc file domain", str(e))
        return []

def process_file(pcap_file, db_name, table_name, allowed_domains):
    csv_file = pcap_file.replace('.pcapng', '_domains.csv').replace('.pcap', '_domains.csv')

    status_label.config(text="🦈 Đang chạy tshark để xuất domain...")
    root.update_idletasks()

    tshark_cmd = [
        "tshark", "-r", pcap_file,
        "-Y", "tls.handshake.extensions_server_name",
        "-T", "fields",
        "-e", "frame.number", "-e", "frame.time_epoch", "-e", "frame.len",
        "-e", "ip.src", "-e", "tcp.srcport", "-e", "udp.srcport",
        "-e", "ip.dst", "-e", "tcp.dstport", "-e", "udp.dstport",
        "-e", "tls.handshake.extensions_server_name"
    ]
    with open(csv_file, 'w', newline='') as f:
        subprocess.run(tshark_cmd, stdout=f)

    try:
        conn = mysql.connector.connect(
            host='localhost',
            user='root',
            password='01012004',
            database=db_name
        )
    except Exception as e:
        messagebox.showerror("Lỗi kết nối MySQL", str(e))
        status_label.config(text="❌ Lỗi kết nối MySQL")
        timer_label.config(text="")
        return

    cursor = conn.cursor()
    status_label.config(text="Đang xử lý và ghi vào MySQL...")
    root.update_idletasks()

    inserted = 0
    with open(csv_file, newline='') as csvfile:
        reader = csv.reader(csvfile, delimiter='\t')
        for row in reader:
            if len(row) < 10:
                continue

            domain = row[9].strip()
            if domain == "" or not is_allowed(domain, allowed_domains):
                continue

            try:
                frame_number = int(row[0])
                time_sec = float(row[1])
                time_full = datetime.fromtimestamp(time_sec)
                length = int(row[2])
                src_ip = row[3]
                dst_ip = row[6]

                if row[4]:
                    src_port = int(row[4])
                    dst_port = int(row[7])
                    protocol = 'TLS'
                elif row[5]:
                    src_port = int(row[5])
                    dst_port = int(row[8])
                    protocol = 'QUIC'
                else:
                    continue

                cursor.execute(f'''
                    INSERT INTO {table_name}
                    (frame_number, time_full, src_ip, src_port, dst_ip, dst_port, protocol, length, domain)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (frame_number, time_full, src_ip, src_port, dst_ip, dst_port, protocol, length, domain))

                inserted += 1

            except Exception as e:
                print(f"[!] Lỗi dòng: {row} → {e}")

    conn.commit()
    conn.close()

    global timer_running
    timer_running = False  # Dừng đồng hồ NGAY tại đây

    total_time = int(time.time() - start_time)
    final_msg = f"Hoàn tất. Đã chèn {inserted} dòng vào bảng `{table_name}` trong {total_time} giây."
    status_label.config(text=final_msg)
    timer_label.config(text="")  # Xóa dòng đếm
    messagebox.showinfo("Hoàn tất", final_msg)


def start_processing():
    def run():
        global start_time, timer_running
        pcap_path = pcap_file_var.get()
        domain_path = domain_file_var.get()
        db_name = db_name_var.get()
        table_name = table_name_var.get()

        if not pcap_path or not domain_path or not db_name or not table_name:
            messagebox.showwarning("Thiếu thông tin", "Vui lòng nhập đầy đủ thông tin.")
            return

        allowed_domains = load_allowed_domains(domain_path)
        if not allowed_domains:
            return

        start_time = time.time()
        timer_running = True
        root.after(1000, update_timer)

        process_file(pcap_path, db_name, table_name, allowed_domains)

        timer_running = False

    threading.Thread(target=run).start()

def choose_pcap():
    path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap *.pcapng")])
    if path:
        pcap_file_var.set(path)

def choose_domain_file():
    path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if path:
        domain_file_var.set(path)

# ===== GIAO DIỆN GUI =====
root = tk.Tk()
root.title("Domain from PCAP to MySQL")
root.geometry("550x580")

pcap_file_var = tk.StringVar()
domain_file_var = tk.StringVar()
db_name_var = tk.StringVar()
table_name_var = tk.StringVar()

ttk.Label(root, text="Chọn file PCAP").pack(pady=5)
ttk.Entry(root, textvariable=pcap_file_var, width=60).pack()
ttk.Button(root, text="Chọn PCAP", command=choose_pcap).pack(pady=5)

ttk.Label(root, text="Chọn file TXT chứa domain cho phép").pack(pady=5)
ttk.Entry(root, textvariable=domain_file_var, width=60).pack()
ttk.Button(root, text="Chọn file domain", command=choose_domain_file).pack(pady=5)

ttk.Label(root, text="Nhập tên database").pack(pady=5)
ttk.Entry(root, textvariable=db_name_var, width=60).pack()

ttk.Label(root, text="Nhập tên bảng").pack(pady=5)
ttk.Entry(root, textvariable=table_name_var, width=60).pack()

ttk.Button(root, text="Bắt đầu xử lý", command=start_processing).pack(pady=10)

status_label = ttk.Label(root, text="", foreground="blue")
status_label.pack()

timer_label = ttk.Label(root, text="", foreground="green")
timer_label.pack()

root.mainloop()
