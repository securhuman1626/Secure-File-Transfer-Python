# server.py (UDP temizlenmiş hali)
import socket
import os
import threading 
from crypto_utils import decrypt_data_aes, sha256, load_private_key, decrypt_aes_key_with_rsa

AUTH_SECRET = b"top_secret_password" 
HASH_SIZE = 32 
PRIVATE_KEY_FILE = "private_key.pem" 

# --- TCP ile Dosya Alma (GUI Callback'leri eklendi) ---
def receive_file_tcp(conn, addr, rsa_private_key, status_callback=None, log_callback=None):
    aes_session_key = None 

    try:
        if log_callback: log_callback(f"TCP: {addr} adresinden bağlantı kabul edildi.")
        
        encrypted_aes_key_length_bytes = conn.recv(2)
        if not encrypted_aes_key_length_bytes:
            if log_callback: log_callback("[-] TCP: Şifreli AES anahtar uzunluğu alınırken bağlantı kesildi.")
            return

        encrypted_aes_key_length = int.from_bytes(encrypted_aes_key_length_bytes, 'big')
        
        encrypted_aes_key = b''
        bytes_received_for_key = 0
        while bytes_received_for_key < encrypted_aes_key_length:
            part = conn.recv(encrypted_aes_key_length - bytes_received_for_key)
            if not part:
                if log_callback: log_callback("[-] TCP: Şifreli AES anahtarı alınırken bağlantı kesildi.")
                return
            encrypted_aes_key += part
            bytes_received_for_key += len(part)

        aes_session_key = decrypt_aes_key_with_rsa(encrypted_aes_key, rsa_private_key)
        if log_callback: log_callback("[+] TCP: AES oturum anahtarı RSA ile çözüldü.")

        name_length_bytes = conn.recv(2)
        if not name_length_bytes:
            if log_callback: log_callback("[-] TCP: Dosya adı uzunluğu alınırken bağlantı kesildi.")
            return
        name_length = int.from_bytes(name_length_bytes, 'big')
        
        filename_bytes = conn.recv(name_length)
        if not filename_bytes:
            if log_callback: log_callback("[-] TCP: Dosya adı alınırken bağlantı kesildi.")
            return
        filename = filename_bytes.decode()
        if log_callback: log_callback(f"[+] TCP: Farklı kaydediliyor: {filename}")

        password = conn.recv(len(AUTH_SECRET))
        if not password:
            if log_callback: log_callback("[-] TCP: Kimlik doğrulama anahtarı alınırken bağlantı kesildi.")
            return
        if password != AUTH_SECRET:
            if log_callback: log_message("[-] TCP: Kimlik doğrulama başarısız.") # Bu satırda hata var, düzelttim
            return
        if log_callback: log_callback("[+] TCP: Kimlik doğrulama başarılı.")

        expected_hash = conn.recv(HASH_SIZE)
        if not expected_hash:
            if log_callback: log_callback("[-] TCP: Hash alınırken bağlantı kesildi.")
            return
        
        full_data = b''
        while True:
            length_data_or_done = conn.recv(4)
            if not length_data_or_done:
                if log_callback: log_callback("[-] TCP: İstemci tarafından bağlantı kapatıldı veya daha fazla veri yok.")
                break

            if length_data_or_done == b'DONE':
                if log_callback: log_callback("[+] TCP: Dosya transferi sonu sinyali alındı.")
                break

            try:
                length = int.from_bytes(length_data_or_done, 'big')
            except ValueError:
                if log_callback: log_callback("[-] TCP: Hata: Parça uzunluğunun beklendiği yerde beklenmedik veri alındı.")
                break

            encrypted_chunk = b''
            bytes_received_for_chunk = 0
            while bytes_received_for_chunk < length:
                part = conn.recv(length - bytes_received_for_chunk)
                if not part:
                    if log_callback: log_callback("[-] TCP: Hata: Parça verisi alınırken bağlantı beklenmedik şekilde kesildi.")
                    break
                encrypted_chunk += part
                bytes_received_for_chunk += len(part)
            
            if bytes_received_for_chunk < length:
                if log_callback: log_callback(f"[-] TCP: Hata: Eksik parça alındı. Beklenen {length}, alınan {bytes_received_for_chunk} bayt.")
                break

            try:
                decrypted = decrypt_data_aes(encrypted_chunk, aes_session_key) 
                full_data += decrypted
            except Exception as e:
                if log_callback: log_callback(f"[-] TCP: Parça şifresi çözülürken hata oluştu: {e}")
                break

        if sha256(full_data) != expected_hash:
            if log_callback: log_callback("[-] TCP: Bütünlük kontrolü başarısız! Alınan hash hesaplanan hash ile eşleşmiyor.")
        else:
            if log_callback: log_callback("[+] TCP: Bütünlük kontrolü başarılı.")
            try:
                with open(filename, 'wb') as f:
                    f.write(full_data)
                if log_callback: log_callback(f"[+] TCP: Dosya alındı, doğrulandı ve '{filename}' olarak kaydedildi.")
            except IOError as e:
                if log_callback: log_callback(f"[-] TCP: Dosya kaydedilirken hata oluştu: {e}")

    except socket.error as e:
        if log_callback: log_callback(f"[-] TCP: Dosya alımı sırasında soket hatası: {e}")
    except Exception as e:
        if log_callback: log_callback(f"[-] TCP: Beklenmedik bir hata oluştu: {e}")
    finally:
        if conn:
            conn.close()
            if log_callback: log_callback("[+] TCP: Bağlantı kapatıldı.")


# --- Ana Sunucu Dinleme Fonksiyonu (Sadece TCP dinleyecek) ---
def start_server_listener(host='0.0.0.0', port=5000, status_callback=None, log_callback=None):
    try:
        rsa_private_key = load_private_key(PRIVATE_KEY_FILE)
        if status_callback: status_callback(f"Özel anahtar '{PRIVATE_KEY_FILE}' yüklendi.")
        if log_callback: log_callback(f"Özel anahtar '{PRIVATE_KEY_FILE}' yüklendi.") 
    except FileNotFoundError:
        error_msg = f"Hata: Özel anahtar '{PRIVATE_KEY_FILE}' bulunamadı. Lütfen 'crypto_utils.py' dosyasını bir kez çalıştırarak anahtarları oluşturun."
        if status_callback: status_callback(error_msg)
        if log_callback: log_callback(error_msg)
        return
    except Exception as e:
        error_msg = f"Hata: Özel anahtar yüklenirken hata oluştu: {e}"
        if status_callback: status_callback(error_msg)
        if log_callback: log_callback(error_msg)
        return

    tcp_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        tcp_s.bind((host, port))
        tcp_s.listen(5) 
        if status_callback: status_callback(f"TCP: {host}:{port} adresinde dinleniyor...")
        if log_callback: log_callback(f"TCP: {host}:{port} adresinde dinleniyor...")
    except socket.error as e:
        error_msg = f"Hata: Sunucu soketi kurulurken hata oluştu: {e}"
        if status_callback: status_callback(error_msg)
        if log_callback: log_callback(error_msg)
        return

    # UDP dinleme thread'i artık başlatılmıyor
    # if status_callback: status_callback(f"UDP: {host}:{udp_port} adresinde dinleme thread'i başlatıldı.") # Bu satırları silin
    # if log_callback: log_callback(f"UDP: {host}:{udp_port} adresinde dinleme thread'i başlatıldı.") # Bu satırları silin

    try:
        while True:
            conn, addr = tcp_s.accept()
            threading.Thread(target=receive_file_tcp, args=(conn, addr, rsa_private_key, status_callback, log_callback)).start()

    except KeyboardInterrupt:
        if status_callback: status_callback("\nSunucu kapatılıyor...")
        if log_callback: log_callback("\nSunucu kapatılıyor...")
    except Exception as e:
        error_msg = f"Beklenmedik bir sunucu hatası: {e}"
        if status_callback: status_callback(error_msg)
        if log_callback: log_callback(error_msg)
    finally:
        tcp_s.close()
        if status_callback: status_callback("Sunucu soketi kapatıldı.")
        if log_callback: log_callback("Sunucu soketi kapatıldı.")