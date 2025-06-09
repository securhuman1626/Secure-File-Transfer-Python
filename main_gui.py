# main_gui.py (UDP temizlenmiş hali)
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import os
import time

# Mevcut client ve server modüllerinizi import edin
import client
import server
from crypto_utils import generate_rsa_keys, save_keys # Anahtar oluşturmak için

# RSA anahtarlarının varlığını kontrol et ve gerekirse oluştur
def setup_rsa_keys():
    public_key_path = "public_key.pem"
    private_key_path = "private_key.pem"
    if not os.path.exists(public_key_path) or not os.path.exists(private_key_path):
        print("[*] RSA anahtarları bulunamadı. Oluşturuluyor...")
        public_key, private_key = generate_rsa_keys()
        save_keys(public_key, private_key, public_file=public_key_path, private_file=private_key_path)
        messagebox.showinfo("Anahtar Oluşturuldu", "RSA anahtar çifti oluşturuldu. Sunucunun açık anahtarını istemci dizinine kopyalayın.")
    else:
        print("[*] RSA anahtarları mevcut.")


class FileTransferApp:
    def __init__(self, master):
        self.master = master
        master.title("Güvenli Dosya Transfer Sistemi")
        master.geometry("600x550") # Pencere boyutu

        # --- Sekmeler ---
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(pady=10, expand=True, fill="both")

        self.send_tab = ttk.Frame(self.notebook)
        self.receive_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.send_tab, text="Dosya Gönder")
        self.notebook.add(self.receive_tab, text="Dosya Al")

        # --- Gönder Sekmesi ---
        self.setup_send_tab()

        # --- Al Sekmesi ---
        self.setup_receive_tab()

        # RSA anahtarlarını kontrol et ve oluştur
        setup_rsa_keys()


    def setup_send_tab(self):
        # Dosya seçme ve gönderme
        tk.Label(self.send_tab, text="Gönderilecek Dosya:").pack(pady=5)
        self.file_path_var = tk.StringVar()
        self.file_entry = tk.Entry(self.send_tab, textvariable=self.file_path_var, width=60)
        self.file_entry.pack(pady=5)

        self.browse_button = tk.Button(self.send_tab, text="Dosya Seç", command=self.browse_file)
        self.browse_button.pack(pady=5)

        tk.Label(self.send_tab, text="Hedef IP:").pack(pady=5)
        self.target_ip_var = tk.StringVar(value="127.0.0.1")
        self.ip_entry = tk.Entry(self.send_tab, textvariable=self.target_ip_var, width=30)
        self.ip_entry.pack(pady=5)

        tk.Label(self.send_tab, text="Hedef Port:").pack(pady=5)
        self.target_port_var = tk.StringVar(value="5000")
        self.port_entry = tk.Entry(self.send_tab, textvariable=self.target_port_var, width=30)
        self.port_entry.pack(pady=5)

        self.send_button = tk.Button(self.send_tab, text="Dosyayı Gönder", command=self.start_send_thread)
        self.send_button.pack(pady=10)

        self.send_status_label = tk.Label(self.send_tab, text="Durum: Bekleniyor...")
        self.send_status_label.pack(pady=5)

        self.send_progress_bar = ttk.Progressbar(self.send_tab, orient="horizontal", length=400, mode="determinate")
        self.send_progress_bar.pack(pady=10)

        self.log_text_send = tk.Text(self.send_tab, height=8, width=70, state="disabled")
        self.log_text_send.pack(pady=5)
        self.log_text_send_scrollbar = tk.Scrollbar(self.send_tab, command=self.log_text_send.yview)
        self.log_text_send_scrollbar.pack(side="right", fill="y")
        self.log_text_send.config(yscrollcommand=self.log_text_send_scrollbar.set)

    def setup_receive_tab(self):
        # Sunucu başlatma
        tk.Label(self.receive_tab, text="Dinlenecek IP:").pack(pady=5)
        self.listen_ip_var = tk.StringVar(value="0.0.0.0")
        self.listen_ip_entry = tk.Entry(self.receive_tab, textvariable=self.listen_ip_var, width=30)
        self.listen_ip_entry.pack(pady=5)

        tk.Label(self.receive_tab, text="Dinlenecek Port:").pack(pady=5)
        self.listen_port_var = tk.StringVar(value="5000")
        self.listen_port_entry = tk.Entry(self.receive_tab, textvariable=self.listen_port_var, width=30)
        self.listen_port_entry.pack(pady=5)

        self.start_server_button = tk.Button(self.receive_tab, text="Sunucuyu Başlat", command=self.start_server_thread)
        self.start_server_button.pack(pady=10)

        self.server_status_label = tk.Label(self.receive_tab, text="Sunucu Durumu: Kapalı")
        self.server_status_label.pack(pady=5)

        self.log_text_receive = tk.Text(self.receive_tab, height=15, width=70, state="disabled")
        self.log_text_receive.pack(pady=5)
        self.log_text_receive_scrollbar = tk.Scrollbar(self.receive_tab, command=self.log_text_receive.yview)
        self.log_text_receive_scrollbar.pack(side="right", fill="y")
        self.log_text_receive.config(yscrollcommand=self.log_text_receive_scrollbar.set)

    def browse_file(self):
        file_selected = filedialog.askopenfilename()
        if file_selected:
            self.file_path_var.set(file_selected)

    def update_send_status(self, message):
        self.master.after(0, lambda: self.send_status_label.config(text=f"Durum: {message}"))

    def update_send_progress(self, value):
        self.master.after(0, lambda: self.send_progress_bar.config(value=value))
        
    def update_server_status(self, message):
        self.master.after(0, lambda: self.server_status_label.config(text=f"Sunucu Durumu: {message}"))

    def log_message(self, text_widget, message):
        self.master.after(0, lambda: self._insert_log_message(text_widget, message))

    def _insert_log_message(self, text_widget, message):
        text_widget.config(state="normal")
        text_widget.insert(tk.END, message + "\n")
        text_widget.see(tk.END) # En alta kaydır
        text_widget.config(state="disabled")

    def start_send_thread(self):
        filename = self.file_path_var.get()
        target_ip = self.target_ip_var.get()
        try:
            target_port = int(self.target_port_var.get())
        except ValueError:
            messagebox.showwarning("Hata", "Geçersiz Port Numarası.")
            return

        if not filename:
            messagebox.showwarning("Uyarı", "Lütfen bir dosya seçin!")
            return
        
        self.update_send_progress(0) # İlerleme çubuğunu sıfırla
        self.update_send_status("Gönderim Başlatılıyor...")
        
        send_thread = threading.Thread(target=self._run_client_send, 
                                       args=(filename, target_ip, target_port, 
                                             self.update_send_status, 
                                             lambda msg: self.log_message(self.log_text_send, msg),
                                             self.update_send_progress))
        send_thread.start()

    def _run_client_send(self, filename, host, port, status_callback, log_callback, progress_callback):
        try:
            # client.py'nin initiate_file_transfer'ı sadece TCP'yi kullanacak
            client.initiate_file_transfer(filename, host, port, status_callback, progress_callback, log_callback)
            
            status_callback("Transfer tamamlandı!")
            log_callback("Transfer tamamlandı!")
        except Exception as e:
            status_callback(f"Hata oluştu: {e}")
            log_callback(f"Hata oluştu: {e}") 
            self.master.after(0, messagebox.showerror, "Transfer Hatası", f"Dosya gönderilirken hata: {e}")


    def start_server_thread(self):
        listen_ip = self.listen_ip_var.get()
        try:
            listen_port = int(self.listen_port_var.get())
        except ValueError:
            messagebox.showwarning("Hata", "Geçersiz Port Numarası.")
            return

        self.update_server_status("Başlatılıyor...")
        server_thread = threading.Thread(target=self._run_server_listener, 
                                         args=(listen_ip, listen_port, 
                                               self.update_server_status, 
                                               lambda msg: self.log_message(self.log_text_receive, msg)))
        server_thread.daemon = True 
        server_thread.start()
        self.master.after(0, lambda: self.start_server_button.config(state="disabled"))
        self.master.after(0, lambda: messagebox.showinfo("Sunucu", f"Sunucu {listen_ip}:{listen_port} adresinde başlatıldı."))


    def _run_server_listener(self, host, port, status_callback, log_callback):
        try:
            # server.start_server_listener artık sadece TCP dinleyecek
            server.start_server_listener(host, port, status_callback, log_callback)
            status_callback("Sunucu durduruldu.")
            log_callback("Sunucu durduruldu.")
            self.master.after(0, lambda: self.start_server_button.config(state="normal"))
        except Exception as e:
            status_callback(f"Hata oluştu: {e}")
            log_callback(f"Hata oluştu: {e}")
            self.master.after(0, messagebox.showerror, "Sunucu Hatası", f"Sunucu başlatılırken/çalışırken hata: {e}")
            self.master.after(0, lambda: self.start_server_button.config(state="normal"))


if __name__ == '__main__':
    root = tk.Tk()
    app = FileTransferApp(root)
    root.mainloop()