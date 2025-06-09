# Gelişmiş Güvenli Dosya Transfer Sistemi

## Proje Tanıtımı

Bu proje, Python programlama dili kullanılarak geliştirilmiş, uçtan uca güvenli dosya transferi sağlayan bir istemci-sunucu uygulamasıdır. Ağ üzerinden hassas verilerin gizliliğini, bütünlüğünü ve kimliğini korumak amacıyla tasarlanmıştır.

## Özellikler

* **Güvenli Anahtar Değişimi:** AES oturum anahtarı, RSA açık anahtar şifrelemesi kullanılarak güvenli bir şekilde aktarılır.
* **Veri Gizliliği:** Dosya içerikleri, güçlü AES (Advanced Encryption Standard) algoritması ile şifrelenir.
* **Veri Bütünlüğü:** Aktarılan dosyaların değiştirilmediğini garanti etmek için SHA256 karma (hash) algoritması ile bütünlük kontrolü yapılır.
* **Kimlik Doğrulama:** Basit bir paylaşılan gizli anahtar mekanizması (`AUTH_SECRET`) ile istemci ve sunucu kimlik doğrulaması.
* **Güvenilir Transfer:** TCP/IP protokolü üzerinden güvenilir ve sıralı veri akışı sağlanır.
* **Dosya Parçalama:** Büyük dosyalar, verimli transfer ve bellek yönetimi için küçük parçalara bölünerek gönderilir.
* **Kullanıcı Dostu Arayüz:** Tkinter kütüphanesi ile geliştirilmiş, sezgisel bir grafiksel kullanıcı arayüzü (GUI) sunar.
* **Ağ Performans Analizi:** Wireshark gibi araçlarla ağ trafiği incelenmiş ve güvenlik mekanizmalarının etkisi gözlemlenmiştir.

## Kullanılan Teknolojiler

* **Python 3.x**
* **Tkinter:** GUI geliştirmesi için
* **`socket` modülü:** Ağ iletişimi için
* **`cryptography` kütüphanesi:** AES ve RSA şifrelemesi, SHA256 hash işlemleri için
* **`os` modülü:** Dosya işlemleri için

## Kurulum ve Çalıştırma

Projeyi yerel makinenizde kurmak ve çalıştırmak için aşağıdaki adımları takip edin:

1.  **Projeyi Klonlayın:**
    ```bash
    git clone [https://github.com/](https://github.com/)[SENİN_GITHUB_KULLANICI_ADINIZ]/Secure-File-Transfer-Python.git
    cd Secure-File-Transfer-Python
    ```
2.  **Gerekli Kütüphaneleri Yükleyin:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **RSA Anahtarlarını Oluşturun:**
    Projenin düzgün çalışması için `private_key.pem` ve `public_key.pem` dosyalarının oluşturulması gerekmektedir. Proje dizininde aşağıdaki komutu çalıştırın:
    ```bash
    python -c "from crypto_utils import generate_rsa_keys; generate_rsa_keys()"
    ```
    
4.  **Uygulamayı Başlatın:**
    GUI'yi başlatmak için `main_gui.py` dosyasını çalıştırın:
    ```bash
    python main_gui.py
    ```

## Kullanım

Uygulama açıldığında, "Dosya Gönder" ve "Dosya Al" olmak üzere iki ana sekme göreceksiniz.

### Dosya Al (Sunucu Tarafı)

1.  "Dosya Al" sekmesine gidin.
2.  Sunucunun dinleyeceği port numarasını girin (örn. `5000`).
3.  "Sunucuyu Başlat" butonuna tıklayın. Sunucu gelen bağlantıları dinlemeye başlayacaktır.

### Dosya Gönder (İstemci Tarafı)

1.  "Dosya Gönder" sekmesine gidin.
2.  Göndermek istediğiniz dosyayı seçmek için "Dosya Seç" butonuna tıklayın.
3.  Hedef IP adresini girin (kendi bilgisayarınızda test ediyorsanız `127.0.0.1`).
4.  Sunucunun dinlediği port numarasını girin (örn. `5000`).
5.  "Dosya Gönder" butonuna tıklayın.

## Güvenlik Analizi

Projenin ağ trafiği, **Wireshark** gibi araçlar kullanılarak analiz edilmiştir. Bu analizler, AES ve RSA şifrelemesinin veri gizliliğini nasıl sağladığını ve TCP/IP protokolünün güvenilir aktarım mekanizmalarını somut olarak göstermiştir. Özellikle, şifrelenmiş veri paketlerinin içeriğinin okunamaz olduğu doğrulanmıştır.
