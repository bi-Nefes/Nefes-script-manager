# Script Manager - Kaynak Kod Dokümantasyonu

Bu doküman, projenin ana dosya ve klasörlerinin ne işe yaradığını ve temel işlevlerin kaynak kodunda nasıl çalıştığını geliştirici gözüyle özetler.

---

## 📁 Klasör ve Dosya Yapısı

```
ssh_script/
├── app.py                # Ana Flask uygulaması ve web sunucusu
├── models.py             # Veritabanı modelleri (SQLAlchemy)
├── scheduler_worker.py   # Zamanlanmış görevleri yöneten worker scripti
├── requirements.txt      # Python bağımlılıkları
├── static/               # Statik dosyalar (JS, CSS, görseller)
├── templates/            # Jinja2 HTML şablonları
```

---

## Ana Dosyalar ve İşlevleri

### 1. **app.py**
- **Flask uygulamasının ana dosyasıdır.**
- Web arayüzü, API endpoint'leri, kullanıcı yönetimi, sunucu/script ekleme, script çalıştırma, log görüntüleme gibi tüm ana işlevler burada tanımlanır.
- **Veritabanı bağlantısı** MariaDB ile sağlanır (`SQLALCHEMY_DATABASE_URI`).
- **Kullanıcı oturumu** Flask-Login ile yönetilir.
- **Profil fotoğrafı yükleme**, dosya upload işlemleri ve validasyon burada yapılır.
- **Zamanlanmış görevler** için (isteğe bağlı) Flask içi scheduler veya ayrı worker ile tetikleme yapılabilir.
- **Önemli fonksiyonlar:**
  - `add_user`, `edit_user`, `delete_user`: Kullanıcı işlemleri
  - `add_server`, `edit_server`, `delete_server`: Sunucu işlemleri
  - `add_script`, `edit_script`, `delete_script`: Script işlemleri
  - `run_script`: Seçili sunucuda script çalıştırma (SSH ile)
  - `dashboard`, `logs`, `scheduler`: Ana sayfa ve log/scheduler arayüzleri
- **Sunucu grupları:** Artık her gruba özel renk (`color`) ve ikon (`icon`) atanabilir. Bu alanlar hem arayüzde badge/ikon olarak gösterilir hem de grup ekleme/düzenleme formlarında seçilebilir.
- **Script çalıştırma:** Script çıktıları, çalıştırma tamamlanınca AJAX ile anında ekranda gösterilir. Sayfa yenilenmeden sonuçlar kullanıcıya sunulur.

### 2. **models.py**
- **Tüm veritabanı modelleri burada tanımlanır.**
- SQLAlchemy ORM kullanılır.
- **Temel modeller:**
  - `User`: Kullanıcılar (rol, şifre, profil fotoğrafı, favori scriptler)
  - `Server`: Sunucular (bağlantı bilgileri, işletim sistemi türü)
  - `Script`: Scriptler (komut, açıklama, parametreler)
  - `Log`: Script çalıştırma kayıtları (tarih, sunucu, script, durum)
  - `ScheduledTask`: Zamanlanmış görevler (cron ifadesi, aktiflik, son/gelecek çalışma zamanı)
  - `TaskChain`, `TaskChainItem`: Zincirleme görevler
  - `MultiTargetTask`, `MultiTargetTaskServer`: Çoklu hedefli görevler
- **Model ilişkileri:**
  - Kullanıcı-favori scriptler (many-to-many, ara tablo: `user_favorites`)
  - Script-parametreler (one-to-many)
  - Sunucu-log, script-log (one-to-many)

### 3. **scheduler_worker.py**
- **Zamanlanmış görevleri arka planda çalıştıran worker scriptidir.**
- Flask uygulamasından bağımsız olarak çalışır.
- Her dakika (veya belirli aralıklarla) aktif zamanlanmış görevleri kontrol eder.
- Görev zamanı gelen scriptleri ilgili sunucuda SSH ile çalıştırır.
- Sonuçları ve durumu loglar.
- **Threading** ile aynı anda birden fazla görevi paralel çalıştırabilir.
- **Not:** Bazı komutlar için çıktıyı beklemeden çalıştırma veya bekleyerek çalıştırma desteği vardır.

### 4. **requirements.txt**
- Projenin çalışması için gerekli Python paketlerini listeler.
- Örnek: Flask, Flask-Login, Flask-SQLAlchemy, Paramiko, PyMySQL, vb.

### 5. **static/**
- **Statik dosyalar burada tutulur.**
- `main.js`, `quick-access.js`, `output-functions.js`: Arayüzdeki dinamik işlemler, hızlı erişim, animasyonlar, script çalıştırma gibi işlevler.
- `dashboard-charts.js`: (Boş/iptal) Eski dashboard grafik kodları, artık kullanılmıyor.
- `uploads/`, `images/`: Profil fotoğrafları ve görseller.

### 6. **templates/**
- **Jinja2 tabanlı HTML şablonları burada bulunur.**
- `base.html`: Tüm sayfaların temel şablonu, navbar, footer, genel CSS/JS.
- `dashboard.html`: Ana sayfa, hızlı erişim, istatistikler.
- `login.html`: Giriş ekranı.
- `users.html`, `user_form.html`: Kullanıcı yönetimi.
- `servers.html`, `server_form.html`: Sunucu yönetimi.
- `scripts.html`, `script_form.html`: Script yönetimi.
- `run_script.html`: Script çalıştırma arayüzü.
- `scheduler.html`, `scheduled_task_form.html`: Zamanlanmış görevler.
- `logs.html`: Çalıştırma kayıtları.
- `profile.html`: Kullanıcı profil ekranı.

---

## 🔄 Temel İş Akışları

### Kullanıcı Girişi ve Yetkilendirme
- Kullanıcılar Flask-Login ile oturum açar.
- Rol tabanlı erişim: admin, manager, user, viewer.
- Her sayfa ve işlem için rol kontrolü yapılır.

### Sunucuya SSH ile Script Çalıştırma
- Kullanıcı arayüzünden sunucu ve script seçer.
- `run_script` fonksiyonu, sunucuya SSH ile bağlanır (Paramiko).
- Script komutu çalıştırılır, çıktı ve durum loglanır.

### Zamanlanmış Görevler
- Kullanıcılar cron ifadesiyle görev tanımlar.
- `scheduler_worker.py` veya Flask içi scheduler, zamanı gelen görevleri tetikler.
- Görevler paralel olarak çalıştırılabilir.

### Loglama ve Raporlama
- Tüm script çalıştırmaları ve zamanlanmış görevler `logs` tablosunda tutulur.
- Loglar arayüzde filtrelenebilir ve görüntülenebilir.

---

## 🛠️ Geliştirici Notları
- **MariaDB dışında SQLite desteği yoktur.**
- **Sunucu şifreleri** düz metin olarak saklanır, production için ek güvenlik önerilir.
- **Profil fotoğrafı yükleme** için `static/uploads/profile_photos/` kullanılır.
- **dashboard-charts.js** dosyası boştur, silinebilir.
- **instance/** ve **app.db** artık yoktur.

---

Daha fazla detay veya belirli bir fonksiyonun açıklaması için dosya/detay belirtmeniz yeterli! 