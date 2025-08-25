-- SSH Script veritabanı kurulum dosyası
-- Bu dosyayı MySQL'de çalıştırın

-- Veritabanını oluştur
CREATE DATABASE IF NOT EXISTS ssh_script CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Kullanıcıyı oluştur
CREATE USER IF NOT EXISTS 'sshuser'@'localhost' IDENTIFIED BY 'gizlisifre';

-- Kullanıcıya yetki ver
GRANT ALL PRIVILEGES ON ssh_script.* TO 'sshuser'@'localhost';

-- Yetkileri uygula
FLUSH PRIVILEGES;

-- Veritabanını seç
USE ssh_script;

-- Kurulum tamamlandı mesajı
SELECT 'SSH Script veritabanı başarıyla kuruldu!' as message; 