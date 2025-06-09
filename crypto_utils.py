# crypto_utils.py
from Crypto.Cipher import AES, PKCS1_OAEP # AES ve RSA için PKCS1_OAEP modlarını içe aktar
from Crypto.PublicKey import RSA # RSA anahtar işlemleri için
from Crypto.Random import get_random_bytes # Güvenli rastgele baytlar üretmek için
import hashlib # Hashleme işlemleri için hashlib modülünü içe aktar

# Sabit anahtar: Bu sadece SHA256 için (kullanılmayacak, RSA ile dinamik olacak)
# KEY = hashlib.sha256(b"my_secret_password").digest() 

# RSA anahtar boyutları
RSA_KEY_SIZE = 2048 # RSA anahtar boyutu (bit olarak)
AES_KEY_SIZE = 32   # AES anahtar boyutu (bayt olarak, 256 bit için)

# RSA Anahtar Yönetimi
def generate_rsa_keys():
    """RSA açık ve özel anahtar çifti üretir."""
    key = RSA.generate(RSA_KEY_SIZE)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

def import_public_key(pem_key):
    """PEM formatındaki açık anahtarı içe aktarır."""
    return RSA.import_key(pem_key)

def import_private_key(pem_key):
    """PEM formatındaki özel anahtarı içe aktarır."""
    return RSA.import_key(pem_key)

def encrypt_aes_key_with_rsa(aes_key, rsa_public_key):
    """AES oturum anahtarını RSA açık anahtarı ile şifreler."""
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key

def decrypt_aes_key_with_rsa(encrypted_aes_key, rsa_private_key):
    """RSA şifreli AES oturum anahtarını özel anahtar ile çözer."""
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return decrypted_aes_key

# AES Şifreleme/Şifre Çözme (Dinamik anahtar kullanılacak)
def encrypt_data_aes(data, aes_key):
    """Veriyi verilen AES anahtarı ile şifreler."""
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

def decrypt_data_aes(encrypted_data, aes_key):
    """Veriyi verilen AES anahtarı ile çözer."""
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def sha256(data):
    """Verinin SHA256 hash'ini hesaplar."""
    return hashlib.sha256(data).digest()

# Anahtar çiftini dosyaya kaydetme ve yükleme fonksiyonları (pratik kullanım için)
def save_keys(public_key, private_key, public_file="public_key.pem", private_file="private_key.pem"):
    """RSA anahtarlarını PEM dosyalarına kaydeder."""
    with open(public_file, "wb") as f:
        f.write(public_key)
    with open(private_file, "wb") as f:
        f.write(private_key)
    print(f"[*] Anahtarlar '{public_file}' ve '{private_file}' olarak kaydedildi.")

def load_public_key(public_file="public_key.pem"):
    """PEM dosyasından açık anahtarı yükler."""
    with open(public_file, "rb") as f:
        return import_public_key(f.read())

def load_private_key(private_file="private_key.pem"):
    """PEM dosyasından özel anahtarı yükler."""
    with open(private_file, "rb") as f:
        return import_private_key(f.read())

# Başlangıçta RSA anahtarlarını oluştur (bir kez çalıştırın)
if __name__ == '__main__':
    public_key, private_key = generate_rsa_keys()
    save_keys(public_key, private_key)
    print("[+] RSA anahtar çifti oluşturuldu ve 'public_key.pem', 'private_key.pem' dosyalarına kaydedildi.")

    # Örnek kullanım:
    # client_aes_key = get_random_bytes(AES_KEY_SIZE)
    # encrypted_aes_key_by_rsa = encrypt_aes_key_with_rsa(client_aes_key, load_public_key("public_key.pem"))
    # decrypted_aes_key_by_rsa = decrypt_aes_key_with_rsa(encrypted_aes_key_by_rsa, load_private_key("private_key.pem"))
    # print(f"Orijinal AES Anahtarı: {client_aes_key.hex()}")
    # print(f"Çözülen AES Anahtarı: {decrypted_aes_key_by_rsa.hex()}")
    # print(f"Anahtarlar Eşleşiyor mu: {client_aes_key == decrypted_aes_key_by_rsa}")