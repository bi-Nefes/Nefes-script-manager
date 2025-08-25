# Script Manager - Kurulum Kılavuzu

## Kurulum Adımları (Türkçe)

### 1. Gereksinimler
- Python 3.8+
- MariaDB veya MySQL
- pip, virtualenv

### 2. MariaDB Kurulumu ve Veritabanı Oluşturma

```bash
sudo apt update && sudo apt install mariadb-server
sudo systemctl start mariadb
sudo mysql_secure_installation
mysql -u root -p

CREATE DATABASE ssh_script CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'sshuser'@'localhost' IDENTIFIED BY 'gizlisifre';
GRANT ALL PRIVILEGES ON ssh_script.* TO 'sshuser'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### 3. Proje Dosyalarını Klonlayın

```bash
git clone <repo-url>
cd ssh_script
```

### 4. Sanal Ortam ve Bağımlılıklar

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 5. Veritabanı Ayarı
`app.py` içinde MariaDB bağlantı URI'sini kontrol edin:
```python
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://sshuser:gizlisifre@localhost/ssh_script?charset=utf8mb4'
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

Uygulama varsayılan olarak 0.0.0.0:5000 adresinde çalışır.

---

## Installation Steps (English)

### 1. Requirements
- Python 3.8+
- MariaDB or MySQL
- pip, virtualenv

### 2. MariaDB Installation and Database Creation

```bash
sudo apt update && sudo apt install mariadb-server
sudo systemctl start mariadb
sudo mysql_secure_installation
mysql -u root -p

CREATE DATABASE ssh_script CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'sshuser'@'localhost' IDENTIFIED BY 'gizlisifre';
GRANT ALL PRIVILEGES ON ssh_script.* TO 'sshuser'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### 3. Clone the Project

```bash
git clone <repo-url>
cd ssh_script
```

### 4. Virtual Environment and Dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 5. Database Configuration
Check the MariaDB URI in `app.py`:
```python
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://sshuser:gizlisifre@localhost/ssh_script?charset=utf8mb4'
```

### 6. Create Database Tables
```bash
python3
>>> from app import app, db
>>> with app.app_context():
...     db.create_all()
... 
>>> exit()
```

### 7. Run the Application
```bash
python3 app.py
```

The app will run on 0.0.0.0:5000 by default. 