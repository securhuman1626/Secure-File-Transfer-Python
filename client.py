# client.py
import socket
import os
import time
from crypto_utils import sha256, encrypt_data_aes, get_random_bytes, AES_KEY_SIZE, load_public_key, encrypt_aes_key_with_rsa

# Eğer Scapy ile IP başlığı manipülasyonu yapacaksanız:
# from scapy.all import IP, TCP, UDP, Raw, send, fragment, get_if_hwaddr, Ether, Packet, bind_layers
# from scapy.compat import raw

CHUNK_SIZE = 1024
AUTH_SECRET = b"top_secret_password"
SERVER_PUBLIC_KEY_FILE = "public_key.pem" # Sunucunun açık anahtar dosyası

# --- Ağ Koşulları Kontrolü (Kavramsal Fonksiyonlar) ---
def check_network_condition_for_tcp():
    """Basit bir ağ koşulu kontrolü. Gerçek implementasyon daha karmaşık olur."""
    return True # Şu an için varsayılan olarak TCP kullanılsın

# --- TCP ile Dosya Gönderme (GUI Callback'leri eklendi) ---
# log_callback parametresi eklendi
def send_file_tcp(filename, host, port, aes_session_key, status_callback=None, progress_callback=None, log_callback=None):
    try:
        with open(filename, 'rb') as f:
            file_data = f.read()
    except FileNotFoundError:
        if status_callback: status_callback(f"Hata: '{filename}' dosyası bulunamadı.")
        if log_callback: log_callback(f"Hata: '{filename}' dosyası bulunamadı.")
        return

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP soketi
    try:
        s.connect((host, port))
        if status_callback: status_callback(f"{host}:{port} adresine bağlandı (TCP).")
        if log_callback: log_callback(f"{host}:{port} adresine bağlandı (TCP).")
    except socket.error as e:
        if status_callback: status_callback(f"Hata: Sunucuya bağlanırken hata: {e}")
        if log_callback: log_callback(f"Hata: Sunucuya bağlanırken hata: {e}") # Loga da yaz
        return

    try:
        # RSA ile AES anahtar değişimi
        server_public_key = load_public_key(SERVER_PUBLIC_KEY_FILE)
        encrypted_aes_key = encrypt_aes_key_with_rsa(aes_session_key, server_public_key)
        
        s.sendall(len(encrypted_aes_key).to_bytes(2, 'big')) 
        s.sendall(encrypted_aes_key)
        if status_callback: status_callback("AES oturum anahtarı RSA ile şifrelenerek gönderildi.")
        if log_callback: log_callback("AES oturum anahtarı RSA ile şifrelenerek gönderildi.")

        # 2. Dosya adını gönder
        file_name_only = os.path.basename(filename)
        s.sendall(len(file_name_only).to_bytes(2, 'big'))
        s.sendall(file_name_only.encode())
        
        # 3. Kimlik doğrulama
        s.sendall(AUTH_SECRET)

        # 4. SHA256 hash gönder
        s.sendall(sha256(file_data))

        # 5. Dosyayı parçala ve şifrele (AES oturum anahtarını kullan)
        offset = 0
        total_size = len(file_data)
        while offset < total_size:
            chunk = file_data[offset:offset + CHUNK_SIZE]
            encrypted_chunk = encrypt_data_aes(chunk, aes_session_key)
            
            s.sendall(len(encrypted_chunk).to_bytes(4, 'big'))
            s.sendall(encrypted_chunk)
            offset += CHUNK_SIZE

            if progress_callback:
                progress_percent = int((offset / total_size) * 100)
                progress_callback(progress_percent)
                # Client tarafında durum label'ı için status_callback'ı main_gui.py kontrol ediyor
                # Tekrarlı mesajları önlemek için burada ayrıca bir status_callback çağrısı yok
                # if status_callback: status_callback(f"Gönderiliyor: {filename} ({progress_percent}%)") 

        # 6. Gönderim bitti
        s.sendall(b'DONE')
        if status_callback: status_callback("Dosya başarıyla gönderildi (TCP).")
        if log_callback: log_callback("Dosya başarıyla gönderildi (TCP).")
    except socket.error as e:
        if status_callback: status_callback(f"Hata: Dosya gönderilirken soket hatası: {e}")
        if log_callback: log_callback(f"Hata: Dosya gönderilirken soket hatası: {e}")
    except Exception as e:
        if status_callback: status_callback(f"Hata: Beklenmedik bir hata oluştu: {e}")
        if log_callback: log_callback(f"Hata: Beklenmedik bir hata oluştu: {e}")
    finally:
        s.close()

# --- UDP ile Dosya Gönderme (Kavramsal - Güvenilirlik Mekanizması EKLEMENİZ GEREKİR) ---
# log_callback parametresi eklendi
def send_file_udp(filename, host, port, aes_session_key, status_callback=None, progress_callback=None, log_callback=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP soketi
    if status_callback: status_callback("UDP transferi başlatılıyor (Güvenilirlik mekanizması eksik!).")
    if log_callback: log_callback("UDP transferi başlatılıyor (Güvenilirlik mekanizması eksik!).")

    try:
        with open(filename, 'rb') as f:
            file_data = f.read()
    except FileNotFoundError:
        if status_callback: status_callback(f"Hata: '{filename}' dosyası bulunamadı.")
        if log_callback: log_callback(f"Hata: '{filename}' dosyası bulunamadı.")
        s.close()
        return

    try:
        server_public_key = load_public_key(SERVER_PUBLIC_KEY_FILE)
        encrypted_aes_key = encrypt_aes_key_with_rsa(aes_session_key, server_public_key)
        
        # UDP ile RSA şifreli anahtarı göndermek için özel bir paket yapısı tanımlayın
        s.sendto(b'\x01' + encrypted_aes_key, (host, port))
        if status_callback: status_callback("AES oturum anahtarı RSA ile şifrelenerek gönderildi (UDP - kavramsal).")
        if log_callback: log_callback("AES oturum anahtarı RSA ile şifrelenerek gönderildi (UDP - kavramsal).")
        time.sleep(0.1)

        # Dosya adını gönder
        file_name_only = os.path.basename(filename)
        s.sendto(b'\x02' + len(file_name_only).to_bytes(2, 'big') + file_name_only.encode(), (host, port))
        if status_callback: status_callback("Dosya adı gönderildi (UDP - kavramsal).")
        if log_callback: log_callback("Dosya adı gönderildi (UDP - kavramsal).")
        time.sleep(0.1)

        # Kimlik doğrulama
        s.sendto(b'\x03' + AUTH_SECRET, (host, port))
        if status_callback: status_callback("Kimlik doğrulama gönderildi (UDP - kavramsal).")
        if log_callback: log_callback("Kimlik doğrulama gönderildi (UDP - kavramsal).")
        time.sleep(0.1)

        # SHA256 hash gönder
        s.sendto(b'\x04' + sha256(file_data), (host, port))
        if status_callback: status_callback("Dosya hash'i gönderildi (UDP - kavramsal).")
        if log_callback: log_callback("Dosya hash'i gönderildi (UDP - kavramsal).")
        time.sleep(0.1)

        # Dosyayı parçala ve şifrele
        offset = 0
        packet_id = 0 # UDP paketleri için bir ID
        total_size = len(file_data)
        while offset < total_size:
            chunk = file_data[offset:offset + CHUNK_SIZE]
            encrypted_chunk = encrypt_data_aes(chunk, aes_session_key)
            
            # UDP paketi yapısı: Tip (0x05 for data) + Paket ID + Uzunluk + Veri
            udp_packet_data = b'\x05' + packet_id.to_bytes(4, 'big') + len(encrypted_chunk).to_bytes(4, 'big') + encrypted_chunk
            
            s.sendto(udp_packet_data, (host, port))
            # BURADA ACK BEKLEME VE YENİDEN İLETİM MANTIĞI OLMALI
            if log_callback: log_callback(f"UDP: Parça {packet_id} gönderildi.")
            
            packet_id += 1
            offset += CHUNK_SIZE
            time.sleep(0.01) # Çok hızlı göndermemek için (test amaçlı)

            if progress_callback:
                progress_percent = int((offset / total_size) * 100)
                progress_callback(progress_percent)

        s.sendto(b'DONE', (host, port)) # DONE sinyali
        if log_callback: log_callback("UDP: 'DONE' sinyali gönderildi.")

    except Exception as e:
        if status_callback: status_callback(f"Hata: UDP dosya gönderilirken hata oluştu: {e}")
        if log_callback: log_callback(f"Hata: UDP dosya gönderilirken hata oluştu: {e}")
    finally:
        s.close()


# --- Ana Transfer Başlatma Fonksiyonu (GUI Callback'leri aldı) ---
# log_callback parametresi eklendi
def initiate_file_transfer(filename, host='127.0.0.1', port=5000, status_callback=None, progress_callback=None, log_callback=None):
    # Her transfer için yeni bir AES oturum anahtarı oluştur
    aes_session_key = get_random_bytes(AES_KEY_SIZE)

    # Ağ koşullarına göre transfer yöntemini seç
    if check_network_condition_for_tcp():
        if status_callback: status_callback("Ağ koşullarına göre TCP kullanılıyor.")
        if log_callback: log_callback("Ağ koşullarına göre TCP kullanılıyor.")
        send_file_tcp(filename, host, port, aes_session_key, status_callback, progress_callback, log_callback)
    else:
        if status_callback: status_callback("Ağ koşullarına göre UDP kullanılıyor (Dikkat: Güvenilir değil!).")
        if log_callback: log_callback("Ağ koşullarına göre UDP kullanılıyor (Dikkat: Güvenilir değil!).")
        send_file_udp(filename, host, port, aes_session_key, status_callback, progress_callback, log_callback)