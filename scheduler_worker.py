#!/usr/bin/env python3
"""
Zamanlanmış görevleri kontrol eden ve çalıştıran worker script.
Bu script Flask uygulamasının içinde çalışır.
"""

import time
import schedule
from datetime import datetime, timezone, timedelta
import logging
from app import app, db
from models import ScheduledTask, Log
import paramiko
import croniter
import threading

# Logging ayarları
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scheduler_worker.log'),
        logging.StreamHandler()
    ]
)

def run_scheduled_task(task_id, now, turkey_tz):
    """Tek bir scheduled task'i thread içinde çalıştırır"""
    from app import app, db
    from models import ScheduledTask, Log
    import paramiko
    import croniter

    # Her thread için yeni Flask app context ve database session
    with app.app_context():
        # Yeni database session oluştur
        from sqlalchemy.orm import scoped_session, sessionmaker
        session_factory = sessionmaker(bind=db.engine)
        Session = scoped_session(session_factory)
        session = Session()

        try:
            # Task'i tekrar çek (thread güvenliği için)
            task = session.get(ScheduledTask, task_id)
            if not task or not task.is_active:
                return

                        server = task.server
                        script = task.script
                        output = ''
                        status = 'success'

                        try:
                            ssh = paramiko.SSHClient()
                            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            ssh.connect(server.host, port=server.port, username=server.username, 
                                       password=server.password, timeout=10)
                            
                # Komutu arka planda başlatma yerine doğrudan çalıştır
                            if script.script_type == 'bash':
                                command = f"bash -c '{script.command}'"
                            elif script.script_type == 'powershell':
                                command = f"powershell -Command \"{script.command}\""
                            elif script.script_type == 'python':
                                command = f"python3 -c '{script.command}'"
                            elif script.script_type == 'nodejs':
                                command = f"node -e '{script.command}'"
                            elif script.script_type == 'php':
                                command = f"php -r '{script.command}'"
                            elif script.script_type == 'ruby':
                                command = f"ruby -e '{script.command}'"
                            elif script.script_type == 'perl':
                                command = f"perl -e '{script.command}'"
                            elif script.script_type == 'exe':
                                exe_command = script.command.strip()
                                if not exe_command.endswith('.exe'):
                                    exe_command += '.exe'
                    command = exe_command
                            else:  # shell
                                command = script.command
                            
                            stdin, stdout, stderr = ssh.exec_command(command)
                # stdout.read()
                # stderr.read()
                ssh.close()

                # Hata kontrolü
                if stderr.channel.recv_exit_status() != 0:
                                status = 'error'

                        except Exception as e:
                            status = 'error'
                logging.error(f"[THREAD] SSH hatası: {e}")

            # Log kaydı (kısa mesaj ile)
            if status == 'success':
                output_message = "Script başarıyla çalıştırıldı"
            else:
                output_message = "Script çalıştırılırken hata oluştu"
            log = Log(server_id=task.server_id, script_id=task.script_id, output=output_message, status=status)
            session.add(log)
                        
                        # Sonraki çalışma zamanını güncelle
                        task.last_run = now
                        cron = croniter.croniter(task.cron_expression, now)
                        next_run = cron.get_next(datetime)
                        task.next_run = next_run.replace(tzinfo=turkey_tz).astimezone(timezone.utc)
                        
            # Değişiklikleri kaydet
            session.commit()
            logging.info(f"[THREAD] Görev çalıştırıldı: {task.name} - {server.name} - {script.name}")

        except Exception as e:
            logging.error(f"[THREAD] Görev çalıştırma hatası: {e}")
            session.rollback()
        finally:
            # Session'ı kapat
            session.close()
            Session.remove()

def check_scheduled_tasks():
    """Zamanlanmış görevleri kontrol eder (thread'li)"""
    with app.app_context():
        try:
            turkey_tz = timezone(timedelta(hours=3))
            now = datetime.now(turkey_tz)
            active_tasks = ScheduledTask.query.filter_by(is_active=True).all()
            executed_count = 0
            
            for task in active_tasks:
                if task.next_run:
                    task_next_run_turkey = task.next_run.replace(tzinfo=timezone.utc).astimezone(turkey_tz)
                    if task_next_run_turkey <= now:
                        # Her görev için ayrı thread başlat
                        t = threading.Thread(target=run_scheduled_task, args=(task.id, now, turkey_tz))
                        t.daemon = True  # Ana program kapandığında thread'ler de kapansın
                        t.start()
                        executed_count += 1
            
            if executed_count > 0:
                logging.info(f"{executed_count} görev thread olarak başlatıldı")
            else:
                logging.info("Çalıştırılacak görev yok")
                
        except Exception as e:
            logging.error(f"Görev kontrolü sırasında hata: {e}")

def main():
    """Ana fonksiyon"""
    logging.info("Zamanlayıcı worker başlatıldı")
    
    # Her dakika görevleri kontrol et
    schedule.every().minute.do(check_scheduled_tasks)
    
    # İlk kontrolü hemen yap
    check_scheduled_tasks()
    
    # Sürekli çalış
    while True:
        try:
            schedule.run_pending()
            time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Worker durduruldu")
            break
        except Exception as e:
            logging.error(f"Worker hatası: {e}")
            time.sleep(60)  # Hata durumunda 1 dakika bekle

if __name__ == "__main__":
    main() 