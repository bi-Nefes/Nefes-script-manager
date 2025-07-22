# NSM NEFES SCRIPT MANAGER

## 🚀 Proje Hakkında

**NSM NEFES Script Manager**, birden fazla sunucuda uzaktan script çalıştırmayı, zamanlanmış görevler oluşturmayı ve sonuçları merkezi olarak yönetmeyi sağlayan modern bir web uygulamasıdır. 

- SSH ile Windows ve Linux sunucularda script çalıştırma
- Zamanlanmış görevler (cron benzeri)
- Kullanıcı yönetimi ve rol tabanlı erişim
- Modern, responsive arayüz (Bootstrap 5)
- MariaDB desteği (SQLite yerine)

---

## 🛠️ Kurulum

### 1. Gereksinimler
- Python 3.8+
- MariaDB (veya MySQL)
- pip, virtualenv

### 2. MariaDB Kurulumu ve Veritabanı Oluşturma

```bash
# MariaDB sunucusunu kurun (Ubuntu/Debian)
sudo apt update && sudo apt install mariadb-server

# MariaDB'yi başlatın ve güvenli kurulum yapın
sudo systemctl start mariadb
sudo mysql_secure_installation

# MariaDB'ye giriş yapın
mysql -u root -p

# Veritabanı ve kullanıcı oluşturun
CREATE DATABASE ssh_script CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'ssh_user'@'localhost' IDENTIFIED BY 'güçlü_bir_şifre';
GRANT ALL PRIVILEGES ON ssh_script.* TO 'ssh_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### 3. Proje Dosyalarını Klonlayın

```bash
git clone <repo-url>
cd ssh_script
```

### 4. Sanal Ortam Oluşturun ve Bağımlılıkları Yükleyin

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 5. `app.py` İçinde Veritabanı Ayarını Yapın

`app.py` dosyasında aşağıdaki gibi MariaDB bağlantı URI'sini kullanın:

```python
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://ssh_user:güçlü_bir_şifre@localhost/ssh_script?charset=utf8mb4'
```

### 6. Veritabanı Tablolarını Oluşturun

```bash
python3
>>> from app import app, db
>>> with app.app_context():
...     db.create_all()
... 
>>> exit()
```

### 7. Uygulamayı Başlatın

```bash
python3 app.py
```

Uygulama varsayılan olarak 0.0.0.0:80 adresinde çalışır.

---

## ⚙️ Özellikler
- SSH ile script çalıştırma (Windows/Linux sunucular)
- Zamanlanmış görevler (cron ifadesiyle)
- Script parametre desteği
- Zincirleme ve çoklu hedef görevler
- Kullanıcı yönetimi, rol ve yetki sistemi
- Profil fotoğrafı yükleme
- Modern dashboard ve log ekranı
- Hızlı erişim (favoriler, son kullanılanlar, popüler scriptler)

---

## 📁 Klasör Yapısı

```
ssh_script/
├── app.py                # Ana Flask uygulaması
├── models.py             # SQLAlchemy modelleri
├── scheduler_worker.py   # Zamanlayıcı worker (isteğe bağlı)
├── requirements.txt      # Bağımlılıklar
├── static/               # Statik dosyalar (JS, CSS)
├── templates/            # Jinja2 HTML şablonları
```

---

## 📝 Notlar
- **SQLite desteği kaldırıldı, sadece MariaDB/MySQL ile çalışır.**
- Sunucuların şifreleri düz metin olarak saklanır, güvenlik için erişimi kısıtlayın.
- Linux ve Windows sunucular desteklenir.
- Zamanlanmış görevler için `scheduler_worker.py` veya Flask içi zamanlayıcı kullanılabilir.

---

## 📞 Destek & Katkı
Sorularınız veya katkı için lütfen [issue açın](https://github.com/your-repo/issues) veya doğrudan iletişime geçin. 