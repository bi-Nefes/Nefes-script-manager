import os
os.environ["FLASK_SKIP_DOTENV"] = "1"
from flask import Flask, render_template, redirect, url_for, request, session, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import db, User, Server, Script, Log, ScheduledTask
import paramiko
from sqlalchemy import or_
from datetime import datetime, timedelta
import croniter
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'  # Bunu production'da değiştirin
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://sshuser:gizlisifre@localhost/ssh_script?charset=utf8mb4'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 20,  # Ana bağlantı havuzu boyutu
    'max_overflow': 30,  # Ek bağlantı sayısı
    'pool_timeout': 30,  # Bağlantı bekleme süresi
    'pool_recycle': 3600,  # Bağlantıları 1 saatte bir yenile
    'pool_pre_ping': True,  # Bağlantı öncesi ping kontrolü
}

# Dosya yükleme ayarları
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads', 'profile_photos')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# Klasörü oluştur (eğer yoksa)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_profile_photo(file, username):
    """Profil fotoğrafını kaydet ve dosya yolunu döndür"""
    if file and allowed_file(file.filename):
        # Güvenli dosya adı oluştur
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = secure_filename(f"{username}_{timestamp}.jpg")
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        
        # Dosyayı kaydet
        file.save(filepath)
        return f"uploads/profile_photos/{filename}"
    return None

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Rol tabanlı erişim kontrolü decorator'ları
def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if not current_user.has_permission(permission):
                flash('Bu işlem için yetkiniz bulunmuyor!', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if not current_user.has_role(role):
                flash('Bu işlem için yetkiniz bulunmuyor!', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_or_404(model, id):
    """SQLAlchemy 2.0 uyumlu get_or_404 fonksiyonu"""
    result = db.session.get(model, id)
    if result is None:
        abort(404)
    return result

# Template filter'ları
@app.template_filter('script_type_color')
def script_type_color(script_type):
    """Script türüne göre renk döndürür"""
    colors = {
        'shell': 'secondary',
        'bash': 'dark',
        'powershell': 'primary',
        'python': 'success',
        'nodejs': 'info',
        'php': 'warning',
        'ruby': 'danger',
        'perl': 'light',
        'exe': 'primary'
    }
    return colors.get(script_type, 'secondary')

@app.template_filter('time_ago')
def time_ago(dt):
    """Zaman önce formatı"""
    if not dt:
        return 'Hiç'
    
    now = datetime.now()
    diff = now - dt
    
    if diff.days > 0:
        return f'{diff.days} gün önce'
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f'{hours} saat önce'
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f'{minutes} dakika önce'
    else:
        return 'Az önce'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if not user.is_active:
                flash('Hesabınız devre dışı bırakılmış!', 'error')
                return render_template('login.html')
            
            login_user(user)
            user.last_login = datetime.now()
            db.session.commit()
            flash(f'Hoş geldiniz, {user.username}! ({user.role_display_name})', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Kullanıcı adı veya şifre hatalı!', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Kullanıcı yönetimi route'ları
@app.route('/users')
@login_required
@permission_required('view_users')
def users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        
        # Kullanıcı adı kontrolü
        if User.query.filter_by(username=username).first():
            flash('Bu kullanıcı adı zaten kullanılıyor!', 'error')
            return render_template('user_form.html', action='add')
        
        # Email kontrolü
        if email and User.query.filter_by(email=email).first():
            flash('Bu email adresi zaten kullanılıyor!', 'error')
            return render_template('user_form.html', action='add')
        
        # Profil fotoğrafı yükleme
        profile_photo = None
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and file.filename:
                profile_photo = save_profile_photo(file, username)
        
        new_user = User(username=username, email=email, role=role, profile_photo=profile_photo)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Kullanıcı eklendi!', 'success')
        return redirect(url_for('users'))
    
    return render_template('user_form.html', action='add')

@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(user_id):
    user = get_or_404(User, user_id)
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']
        is_active = 'is_active' in request.form
        
        # Kullanıcı adı kontrolü (kendisi hariç)
        existing_user = User.query.filter_by(username=username).first()
        if existing_user and existing_user.id != user.id:
            flash('Bu kullanıcı adı zaten kullanılıyor!', 'error')
            return render_template('user_form.html', action='edit', user=user)
        
        # Email kontrolü (kendisi hariç)
        if email:
            existing_email = User.query.filter_by(email=email).first()
            if existing_email and existing_email.id != user.id:
                flash('Bu email adresi zaten kullanılıyor!', 'error')
                return render_template('user_form.html', action='edit', user=user)
        
        user.username = username
        user.email = email
        user.role = role
        user.is_active = is_active
        
        # Profil fotoğrafı yükleme
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and file.filename:
                profile_photo = save_profile_photo(file, username)
                if profile_photo:
                    user.profile_photo = profile_photo
        
        # Şifre değişikliği
        if request.form.get('password'):
            user.set_password(request.form['password'])
        
        db.session.commit()
        flash('Kullanıcı güncellendi!', 'success')
        return redirect(url_for('users'))
    
    return render_template('user_form.html', action='edit', user=user)

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(user_id):
    user = get_or_404(User, user_id)
    
    # Kendini silmeye çalışıyorsa engelle
    if user.id == current_user.id:
        flash('Kendinizi silemezsiniz!', 'error')
        return redirect(url_for('users'))
    
    db.session.delete(user)
    db.session.commit()
    flash('Kullanıcı silindi!', 'success')
    return redirect(url_for('users'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        email = request.form['email']
        
        # Email kontrolü (kendisi hariç)
        if email:
            existing_email = User.query.filter_by(email=email).first()
            if existing_email and existing_email.id != current_user.id:
                flash('Bu email adresi zaten kullanılıyor!', 'error')
                return render_template('profile.html')
        
        current_user.email = email
        
        # Şifre değişikliği
        if request.form.get('new_password'):
            if not current_user.check_password(request.form['current_password']):
                flash('Mevcut şifre hatalı!', 'error')
                return render_template('profile.html')
            current_user.set_password(request.form['new_password'])
        
        db.session.commit()
        flash('Profil güncellendi!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('profile.html')

@app.route('/')
@login_required
def dashboard():
    # İstatistikler için verileri çek
    servers = Server.query.all()
    scripts = Script.query.all()
    tasks = ScheduledTask.query.filter_by(is_active=True).all()
    logs = Log.query.all()
    recent_logs = Log.query.order_by(Log.timestamp.desc()).limit(5).all()
    
    # Hızlı erişim için veriler
    recent_scripts = Script.query.filter(Script.last_used.isnot(None)).order_by(Script.last_used.desc()).limit(8).all()
    popular_scripts = Script.query.order_by(Script.usage_count.desc()).limit(8).all()
    
    # Bugün çalışacak görevleri hesapla
    from datetime import datetime, timedelta, timezone
    import croniter
    
    turkey_tz = timezone(timedelta(hours=3))
    today = datetime.now(turkey_tz).date()
    today_start = datetime.combine(today, datetime.min.time()).replace(tzinfo=turkey_tz)
    today_end = datetime.combine(today, datetime.max.time()).replace(tzinfo=turkey_tz)
    
    today_tasks = []
    for task in tasks:
        try:
            cron = croniter.croniter(task.cron_expression, today_start)
            next_run = cron.get_next(datetime)
            if today_start <= next_run <= today_end:
                today_tasks.append({
                    'task': task,
                    'next_run': next_run,
                    'time_str': next_run.strftime('%H:%M')
                })
        except Exception as e:
            continue
    today_tasks.sort(key=lambda x: x['next_run'])
    
    # Grafik verilerini hazırla
    from sqlalchemy import func
    
    # Sunucu bazında çalışma sayısı
    server_usage = db.session.query(
        Server.name,
        func.count(Log.id).label('count')
    ).outerjoin(Log, Server.id == Log.server_id).group_by(Server.id, Server.name).all()
    
    # Script türü dağılımı
    script_types = db.session.query(
        Script.script_type,
        func.count(Script.id).label('count')
    ).group_by(Script.script_type).all()
    
    # Son 7 günün günlük çalışma sayısı
    daily_executions = []
    for i in range(7):
        date = datetime.now().date() - timedelta(days=i)
        count = Log.query.filter(
            func.date(Log.timestamp) == date
        ).count()
        daily_executions.append(count)
    daily_executions.reverse()  # En eski tarihten en yeniye
    
    # Son 30 günün aylık aktivite sayısı
    monthly_activity = []
    for i in range(30):
        date = datetime.now().date() - timedelta(days=i)
        count = Log.query.filter(
            func.date(Log.timestamp) == date
        ).count()
        monthly_activity.append(count)
    monthly_activity.reverse()  # En eski tarihten en yeniye
    
    # Şu anki zaman (Türkiye saat dilimi)
    from datetime import timezone, timedelta
    turkey_tz = timezone(timedelta(hours=3))
    current_time = datetime.now(turkey_tz).strftime('%H:%M')
    
    return render_template('dashboard.html', 
                         servers=servers, 
                         scripts=scripts, 
                         tasks=tasks, 
                         logs=logs, 
                         recent_logs=recent_logs,
                         current_time=current_time,
                         server_usage=server_usage,
                         script_types=script_types,
                         daily_executions=daily_executions,
                         monthly_activity=monthly_activity,
                         timedelta=timedelta,
                         recent_scripts=recent_scripts,
                         popular_scripts=popular_scripts,
                         today_tasks=today_tasks)

@app.route('/servers')
@login_required
def servers():
    servers = Server.query.all()
    return render_template('servers.html', servers=servers)

@app.route('/servers/add', methods=['GET', 'POST'])
@login_required
@permission_required('add_server')
def add_server():
    if request.method == 'POST':
        name = request.form['name']
        host = request.form['host']
        port = request.form['port']
        username = request.form['username']
        password = request.form['password']
        new_server = Server(name=name, host=host, port=port, username=username, password=password)
        db.session.add(new_server)
        db.session.commit()
        flash('Sunucu eklendi!', 'success')
        return redirect(url_for('servers'))
    return render_template('server_form.html', action='add')

@app.route('/servers/edit/<int:server_id>', methods=['GET', 'POST'])
@login_required
@permission_required('edit_server')
def edit_server(server_id):
    server = get_or_404(Server, server_id)
    if request.method == 'POST':
        server.name = request.form['name']
        server.host = request.form['host']
        server.port = request.form['port']
        server.username = request.form['username']
        server.password = request.form['password']
        db.session.commit()
        flash('Sunucu güncellendi!', 'success')
        return redirect(url_for('servers'))
    return render_template('server_form.html', action='edit', server=server)

@app.route('/servers/delete/<int:server_id>', methods=['POST'])
@login_required
@permission_required('delete_server')
def delete_server(server_id):
    server = get_or_404(Server, server_id)
    # 1. Grup üyeliklerini sil
    # for membership in list(server.group_memberships):
    #     db.session.delete(membership)
    # 2. Zincir görevlerini sil
    from models import TaskChainItem, MultiTargetTaskServer, Log, ScheduledTask
    TaskChainItem.query.filter_by(server_id=server.id).delete()
    # 3. Multi-target görev ilişkilerini sil
    MultiTargetTaskServer.query.filter_by(server_id=server.id).delete()
    # 4. Logları sil
    Log.query.filter_by(server_id=server.id).delete()
    # 5. Zamanlanmış görevleri sil
    ScheduledTask.query.filter_by(server_id=server.id).delete()
    db.session.delete(server)
    db.session.commit()
    flash('Sunucu silindi!', 'success')
    return redirect(url_for('servers'))

@app.route('/scripts')
@login_required
def scripts():
    scripts = Script.query.all()
    return render_template('scripts.html', scripts=scripts)

@app.route('/scripts/add', methods=['GET', 'POST'])
@login_required
@permission_required('add_script')
def add_script():
    if request.method == 'POST':
        name = request.form['name']
        command = request.form['command']
        description = request.form['description']
        script_type = request.form['script_type']
        new_script = Script(name=name, command=command, description=description, script_type=script_type)
        db.session.add(new_script)
        db.session.commit()
        flash('Script eklendi!', 'success')
        return redirect(url_for('scripts'))
    return render_template('script_form.html', action='add')

@app.route('/scripts/edit/<int:script_id>', methods=['GET', 'POST'])
@login_required
@permission_required('edit_script')
def edit_script(script_id):
    script = get_or_404(Script, script_id)
    if request.method == 'POST':
        script.name = request.form['name']
        script.command = request.form['command']
        script.description = request.form['description']
        script.script_type = request.form['script_type']
        db.session.commit()
        flash('Script güncellendi!', 'success')
        return redirect(url_for('scripts'))
    return render_template('script_form.html', action='edit', script=script)

@app.route('/scripts/delete/<int:script_id>', methods=['POST'])
@login_required
@permission_required('delete_script')
def delete_script(script_id):
    script = get_or_404(Script, script_id)
    from models import ScheduledTask, Log, TaskChainItem, MultiTargetTaskServer
    # 1. Zamanlanmış görevleri sil
    ScheduledTask.query.filter_by(script_id=script.id).delete()
    # 2. Logları sil
    Log.query.filter_by(script_id=script.id).delete()
    # 3. Zincir görevleri sil
    TaskChainItem.query.filter_by(script_id=script.id).delete()
    # 4. Multi-target görev ilişkilerini sil
    MultiTargetTaskServer.query.filter_by(server_id=script.id).delete()  # Not: Eğer script_id ile ilişkili ise ayrıca kontrol edilmeli
    db.session.delete(script)
    db.session.commit()
    flash('Script silindi!', 'success')
    return redirect(url_for('scripts'))

@app.route('/run', methods=['GET', 'POST'])
@login_required
@permission_required('run_script')
def run_script():
    servers = Server.query.all()
    scripts = Script.query.all()
    outputs = []  # Her sunucu için çıktı ve durum
    selected_servers = []
    selected_scripts = []
    
    if request.method == 'POST':
        server_ids = request.form.getlist('server_id')
        script_ids = request.form.getlist('script_ids')
        execution_mode = request.form.get('execution_mode', 'parallel')
        
        if not script_ids:
            flash('En az bir script seçmelisiniz!', 'error')
            return render_template('run_script.html', servers=servers, scripts=scripts)
        
        if not server_ids:
            flash('En az bir sunucu seçmelisiniz!', 'error')
            return render_template('run_script.html', servers=servers, scripts=scripts)
        
        # Scriptleri ve sunucuları al
        selected_scripts = [db.session.get(Script, sid) for sid in script_ids]
        selected_servers = [db.session.get(Server, sid) for sid in server_ids]
        
        # Çalıştırma moduna göre scriptleri çalıştır
        if execution_mode == 'parallel':
            outputs = execute_scripts_parallel(selected_scripts, selected_servers)
        elif execution_mode == 'sequential':
            outputs = execute_scripts_sequential(selected_scripts, selected_servers)
        elif execution_mode == 'conditional':
            outputs = execute_scripts_conditional(selected_scripts, selected_servers)
        else:
            outputs = execute_scripts_parallel(selected_scripts, selected_servers)
    
    return render_template('run_script.html', servers=servers, scripts=scripts, outputs=outputs, selected_servers=selected_servers, selected_scripts=selected_scripts)

def execute_scripts_parallel(scripts, servers):
    """Scriptleri paralel olarak çalıştır"""
    import threading
    import queue
    import time
    
    outputs = []
    output_queue = queue.Queue()
    completed_tasks = 0
    total_tasks = len(scripts) * len(servers)
    
    def run_script_on_server(script, server):
        nonlocal completed_tasks
        output = ''
        status = 'success'
        start_time = time.time()
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(server.host, port=server.port, username=server.username, password=server.password, timeout=30)
            
            # Script türüne göre komut hazırla
            command = prepare_command(script)
            
            # Komutun çıktısını bekle
            stdin, stdout, stderr = ssh.exec_command(command)
            def safe_decode(data):
                if not data:
                    return ''
                try:
                    return data.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        return data.decode('windows-1254')
                    except UnicodeDecodeError:
                        try:
                            return data.decode('iso-8859-9')
                        except UnicodeDecodeError:
                            try:
                                return data.decode('windows-1252')
                            except UnicodeDecodeError:
                                return data.decode('utf-8', errors='replace')
            out = safe_decode(stdout.read())
            err = safe_decode(stderr.read())
            output = out + ('\n' + err if err else '')
            if err:
                status = 'error'
            ssh.close()
            
            # Script kullanım sayısını artır
            script.usage_count += 1
            script.last_used = datetime.now()
            
            execution_time = time.time() - start_time
            
            # Log kaydı oluştur
            log = Log(
                server_id=server.id,
                script_id=script.id,
                output=output,
                status=status,
                execution_type='parallel',
                execution_time=execution_time
            )
            db.session.add(log)
            
        except Exception as e:
            output = f"Hata: {str(e)}"
            status = 'error'
            execution_time = time.time() - start_time
            
            # Hata log kaydı oluştur
            log = Log(
                server_id=server.id,
                script_id=script.id,
                output=output,
                status=status,
                execution_type='parallel',
                execution_time=execution_time
            )
            db.session.add(log)
        
        # Tamamlanan görev sayısını artır
        completed_tasks += 1
        
        output_queue.put({
            'server': server,
            'script': script,
            'output': output,
            'status': status,
            'execution_time': execution_time
        })
    
    # Tüm script-sunucu kombinasyonları için thread oluştur
    threads = []
    for script in scripts:
        for server in servers:
            thread = threading.Thread(target=run_script_on_server, args=(script, server))
            threads.append(thread)
            thread.start()
    
    # Tüm threadlerin bitmesini bekle
    for thread in threads:
        thread.join()
    
    # Sonuçları topla
    while not output_queue.empty():
        outputs.append(output_queue.get())
    
    db.session.commit()
    return outputs

def execute_scripts_sequential(scripts, servers):
    """Scriptleri sıralı olarak çalıştır"""
    import time
    outputs = []
    
    for script in scripts:
        for server in servers:
            output = ''
            status = 'success'
            start_time = time.time()
            
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(server.host, port=server.port, username=server.username, password=server.password, timeout=30)
                
                # Script türüne göre komut hazırla
                command = prepare_command(script)
                
                # Komutun çıktısını bekle
                stdin, stdout, stderr = ssh.exec_command(command)
                def safe_decode(data):
                    if not data:
                        return ''
                    try:
                        return data.decode('utf-8')
                    except UnicodeDecodeError:
                        try:
                            return data.decode('windows-1254')
                        except UnicodeDecodeError:
                            try:
                                return data.decode('iso-8859-9')
                            except UnicodeDecodeError:
                                try:
                                    return data.decode('windows-1252')
                                except UnicodeDecodeError:
                                    return data.decode('utf-8', errors='replace')
                out = safe_decode(stdout.read())
                err = safe_decode(stderr.read())
                output = out + ('\n' + err if err else '')
                if err:
                    status = 'error'
                ssh.close()
                
                # Script kullanım sayısını artır
                script.usage_count += 1
                script.last_used = datetime.now()
                
                execution_time = time.time() - start_time
                
                # Log kaydı oluştur
                log = Log(
                    server_id=server.id,
                    script_id=script.id,
                    output=output,
                    status=status,
                    execution_type='sequential',
                    execution_time=execution_time
                )
                db.session.add(log)
                
            except Exception as e:
                output = f"Hata: {str(e)}"
                status = 'error'
                execution_time = time.time() - start_time
                
                # Hata log kaydı oluştur
                log = Log(
                    server_id=server.id,
                    script_id=script.id,
                    output=output,
                    status=status,
                    execution_type='sequential',
                    execution_time=execution_time
                )
                db.session.add(log)
            
            outputs.append({
                'server': server,
                'script': script,
                'output': output,
                'status': status,
                'execution_time': execution_time
            })
    
    db.session.commit()
    return outputs

def execute_scripts_conditional(scripts, servers):
    """Scriptleri koşullu olarak çalıştır (başarılı olursa devam et)"""
    import time
    outputs = []
    
    for script in scripts:
        script_success = True  # Bu script için genel başarı durumu
        
        for server in servers:
            output = ''
            status = 'success'
            start_time = time.time()
            
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(server.host, port=server.port, username=server.username, password=server.password, timeout=30)
                
                # Script türüne göre komut hazırla
                command = prepare_command(script)
                
                # Komutun çıktısını bekle
                stdin, stdout, stderr = ssh.exec_command(command)
                def safe_decode(data):
                    if not data:
                        return ''
                    try:
                        return data.decode('utf-8')
                    except UnicodeDecodeError:
                        try:
                            return data.decode('windows-1254')
                        except UnicodeDecodeError:
                            try:
                                return data.decode('iso-8859-9')
                            except UnicodeDecodeError:
                                try:
                                    return data.decode('windows-1252')
                                except UnicodeDecodeError:
                                    return data.decode('utf-8', errors='replace')
                out = safe_decode(stdout.read())
                err = safe_decode(stderr.read())
                output = out + ('\n' + err if err else '')
                if err:
                    status = 'error'
                ssh.close()
                
                # Script kullanım sayısını artır
                script.usage_count += 1
                script.last_used = datetime.now()
                
                execution_time = time.time() - start_time
                
                # Log kaydı oluştur
                log = Log(
                    server_id=server.id,
                    script_id=script.id,
                    output=output,
                    status=status,
                    execution_type='conditional',
                    execution_time=execution_time
                )
                db.session.add(log)
                
            except Exception as e:
                output = f"Hata: {str(e)}"
                status = 'error'
                script_success = False
                execution_time = time.time() - start_time
                
                # Hata log kaydı oluştur
                log = Log(
                    server_id=server.id,
                    script_id=script.id,
                    output=output,
                    status=status,
                    execution_type='conditional',
                    execution_time=execution_time
                )
                db.session.add(log)
            
            outputs.append({
                'server': server,
                'script': script,
                'output': output,
                'status': status,
                'execution_time': execution_time
            })
        
        # Eğer bu script başarısız olduysa, sonraki scriptleri atla
        if not script_success:
            break
    
    db.session.commit()
    return outputs

def prepare_command(script):
    """Script türüne göre komut hazırla"""
    if script.script_type == 'bash':
        return f"bash -c '{script.command}'"
    elif script.script_type == 'powershell':
        return f"powershell -Command \"{script.command}\""
    elif script.script_type == 'python':
        return f"python3 -c '{script.command}'"
    elif script.script_type == 'nodejs':
        return f"node -e '{script.command}'"
    elif script.script_type == 'php':
        return f"php -r '{script.command}'"
    elif script.script_type == 'ruby':
        return f"ruby -e '{script.command}'"
    elif script.script_type == 'perl':
        return f"perl -e '{script.command}'"
    elif script.script_type == 'exe':
        # Windows EXE dosyaları için tam yol belirtme
        exe_command = script.command.strip()
        if not exe_command.endswith('.exe'):
            exe_command += '.exe'
        
        # Eğer tam yol belirtilmemişse, PATH'te ara
        if not exe_command.startswith('\\') and not exe_command.startswith('C:'):
            # Önce System32'de ara
            return f"cmd /c \"{exe_command}\""
        else:
            # Tam yol belirtilmişse direkt çalıştır
            return f"cmd /c \"{exe_command}\""
    else:  # shell
        return script.command

@app.route('/logs')
@login_required
def logs():
    servers = Server.query.all()
    scripts = Script.query.all()
    server_id = request.args.get('server_id', type=int)
    script_id = request.args.get('script_id', type=int)
    query = Log.query
    if server_id:
        query = query.filter(Log.server_id == server_id)
    if script_id:
        query = query.filter(Log.script_id == script_id)
    logs = query.order_by(Log.timestamp.desc()).all()
    return render_template('logs.html', logs=logs, servers=servers, scripts=scripts, selected_server=server_id, selected_script=script_id, timedelta=timedelta)

@app.route('/logs/delete/<int:log_id>', methods=['POST'])
@login_required
@permission_required('delete_log')
def delete_log(log_id):
    log = get_or_404(Log, log_id)
    db.session.delete(log)
    db.session.commit()
    flash('Log kaydı silindi!', 'success')
    return redirect(url_for('logs'))

@app.route('/logs/delete_all', methods=['POST'])
@login_required
@permission_required('delete_log')
def delete_all_logs():
    server_id = request.form.get('server_id', type=int)
    script_id = request.form.get('script_id', type=int)
    
    query = Log.query
    if server_id:
        query = query.filter(Log.server_id == server_id)
    if script_id:
        query = query.filter(Log.script_id == script_id)
    
    deleted_count = query.count()
    query.delete()
    db.session.commit()
    
    flash(f'{deleted_count} log kaydı silindi!', 'success')
    return redirect(url_for('logs'))

@app.route('/scheduler')
@login_required
def scheduler():
    from datetime import timezone, timedelta
    turkey_tz = timezone(timedelta(hours=3))
    
    # Veritabanından UTC olarak gelen zamanları Türkiye saatine çevir
    tasks = ScheduledTask.query.all()
    for task in tasks:
        if task.next_run:
            # UTC'den Türkiye saatine çevir
            task.next_run = task.next_run.replace(tzinfo=timezone.utc).astimezone(turkey_tz)
    
    return render_template('scheduler.html', tasks=tasks, timedelta=timedelta)

@app.route('/scheduler/add', methods=['GET', 'POST'])
@login_required
@permission_required('add_scheduled_task')
def add_scheduled_task():
    servers = Server.query.all()
    scripts = Script.query.all()
    if request.method == 'POST':
        name = request.form['name']
        server_id = request.form['server_id']
        script_id = request.form['script_id']
        cron_expression = request.form['cron_expression']
        is_active = 'is_active' in request.form
        
        # Sonraki çalışma zamanını hesapla (Türkiye saati için)
        from datetime import timezone, timedelta
        turkey_tz = timezone(timedelta(hours=3))
        now_turkey = datetime.now(turkey_tz)
        cron = croniter.croniter(cron_expression, now_turkey)
        next_run = cron.get_next(datetime)
        # UTC'ye çevir (veritabanında UTC olarak sakla)
        next_run_utc = next_run.replace(tzinfo=turkey_tz).astimezone(timezone.utc)
        
        task = ScheduledTask(
            name=name, server_id=server_id, script_id=script_id,
            cron_expression=cron_expression, is_active=is_active, next_run=next_run_utc
        )
        db.session.add(task)
        db.session.commit()
        flash('Zamanlanmış görev eklendi!', 'success')
        return redirect(url_for('scheduler'))
    return render_template('scheduled_task_form.html', action='add', servers=servers, scripts=scripts)

@app.route('/scheduler/edit/<int:task_id>', methods=['GET', 'POST'])
@login_required
@permission_required('edit_scheduled_task')
def edit_scheduled_task(task_id):
    task = get_or_404(ScheduledTask, task_id)
    servers = Server.query.all()
    scripts = Script.query.all()
    if request.method == 'POST':
        task.name = request.form['name']
        task.server_id = request.form['server_id']
        task.script_id = request.form['script_id']
        task.cron_expression = request.form['cron_expression']
        task.is_active = 'is_active' in request.form
        
        # Sonraki çalışma zamanını yeniden hesapla (Türkiye saati için)
        from datetime import timezone, timedelta
        turkey_tz = timezone(timedelta(hours=3))
        now_turkey = datetime.now(turkey_tz)
        cron = croniter.croniter(task.cron_expression, now_turkey)
        next_run = cron.get_next(datetime)
        # UTC'ye çevir (veritabanında UTC olarak sakla)
        task.next_run = next_run.replace(tzinfo=turkey_tz).astimezone(timezone.utc)
        
        db.session.commit()
        flash('Zamanlanmış görev güncellendi!', 'success')
        return redirect(url_for('scheduler'))
    return render_template('scheduled_task_form.html', action='edit', task=task, servers=servers, scripts=scripts)

@app.route('/scheduler/delete/<int:task_id>', methods=['POST'])
@login_required
@permission_required('delete_scheduled_task')
def delete_scheduled_task(task_id):
    task = get_or_404(ScheduledTask, task_id)
    db.session.delete(task)
    db.session.commit()
    flash('Zamanlanmış görev silindi!', 'success')
    return redirect(url_for('scheduler'))

@app.route('/scheduler/run/<int:task_id>', methods=['POST'])
@login_required
@permission_required('run_scheduled_task')
def run_scheduled_task(task_id):
    task = get_or_404(ScheduledTask, task_id)
    server = task.server
    script = task.script
    
    output = ''
    status = 'success'
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(server.host, port=server.port, username=server.username, 
                   password=server.password, timeout=10)
        
        # Script türüne göre komut hazırla
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
            # Windows EXE dosyaları için tam yol belirtme
            exe_command = script.command.strip()
            if not exe_command.endswith('.exe'):
                exe_command += '.exe'
            
            # Eğer tam yol belirtilmemişse, PATH'te ara
            if not exe_command.startswith('\\') and not exe_command.startswith('C:'):
                # Önce System32'de ara
                command = f"cmd /c \"{exe_command}\""
            else:
                # Tam yol belirtilmişse direkt çalıştır
                command = f"cmd /c \"{exe_command}\""
        else:
            command = script.command
        
        # Komutun çıktısını bekle
        stdin, stdout, stderr = ssh.exec_command(command)
        def safe_decode(data):
            if not data:
                return ''
            try:
                return data.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    return data.decode('windows-1254')
                except UnicodeDecodeError:
                    try:
                        return data.decode('iso-8859-9')
                    except UnicodeDecodeError:
                        try:
                            return data.decode('windows-1252')
                        except UnicodeDecodeError:
                            return data.decode('utf-8', errors='replace')
        out = safe_decode(stdout.read())
        err = safe_decode(stderr.read())
        output = out + ('\n' + err if err else '')
        if err:
            status = 'error'
        ssh.close()
    except Exception as e:
        output = str(e)
        status = 'error'
    
    # Log kaydı
    log = Log(server_id=task.server_id, script_id=task.script_id, output=output, status=status)
    db.session.add(log)
    
    # Sonraki çalışma zamanını güncelle (Türkiye saati için)
    from datetime import timezone, timedelta
    turkey_tz = timezone(timedelta(hours=3))
    now_turkey = datetime.now(turkey_tz)
    task.last_run = now_turkey
    cron = croniter.croniter(task.cron_expression, now_turkey)
    next_run = cron.get_next(datetime)
    # UTC'ye çevir (veritabanında UTC olarak sakla)
    task.next_run = next_run.replace(tzinfo=turkey_tz).astimezone(timezone.utc)
    
    db.session.commit()
    flash('Zamanlanmış görev çalıştırıldı!', 'success')
    return redirect(url_for('scheduler'))

@app.route('/servers/test/<int:server_id>', methods=['POST'])
@login_required
def test_server_connection(server_id):
    server = get_or_404(Server, server_id)
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(server.host, port=server.port, username=server.username, 
                   password=server.password, timeout=10)
        ssh.close()
        return {'status': 'success', 'message': f'{server.name} sunucusuna bağlantı başarılı!'}
    except Exception as e:
        return {'status': 'error', 'message': f'Bağlantı hatası: {str(e)}'}

# API Route'ları
@app.route('/api/servers')
@login_required
def api_servers():
    servers = Server.query.all()
    return jsonify([{
        'id': server.id,
        'name': server.name,
        'host': server.host
    } for server in servers])

@app.route('/api/quick-run', methods=['POST'])
@login_required
@permission_required('run_script')
def api_quick_run():
    data = request.get_json()
    script_id = data.get('script_id')
    server_id = data.get('server_id')
    
    if not script_id or not server_id:
        return jsonify({'status': 'error', 'message': 'Script ID ve Server ID gerekli'})
    
    try:
        script = get_or_404(Script, script_id)
        server = get_or_404(Server, server_id)
        
        # Script kullanım sayısını artır
        script.usage_count += 1
        script.last_used = datetime.now()
        
        # SSH bağlantısı ve script çalıştırma
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(server.host, port=server.port, username=server.username, 
                   password=server.password, timeout=30)
        
        # Script türüne göre komut hazırla
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
            if not exe_command.startswith('\\') and not exe_command.startswith('C:'):
                command = f"cmd /c \"{exe_command}\""
            else:
                command = f"cmd /c \"{exe_command}\""
        else:
            command = script.command
        
        # Komutun çıktısını bekle
        stdin, stdout, stderr = ssh.exec_command(command)
        def safe_decode(data):
            if not data:
                return ''
            try:
                return data.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    return data.decode('windows-1254')
                except UnicodeDecodeError:
                    try:
                        return data.decode('iso-8859-9')
                    except UnicodeDecodeError:
                        try:
                            return data.decode('windows-1252')
                        except UnicodeDecodeError:
                            return data.decode('utf-8', errors='replace')
        out = safe_decode(stdout.read())
        err = safe_decode(stderr.read())
        output = out + ('\n' + err if err else '')
        if err:
            status = 'error'
        ssh.close()
        
        # Log kaydı
        log = Log(server_id=server_id, script_id=script_id, output=output, status=status)
        db.session.add(log)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Script başarıyla çalıştırıldı'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/favorites/add', methods=['POST'])
@login_required
def api_add_favorite():
    data = request.get_json()
    script_id = data.get('script_id')
    
    if not script_id:
        return jsonify({'status': 'error', 'message': 'Script ID gerekli'})
    
    try:
        script = get_or_404(Script, script_id)
        if script not in current_user.favorite_scripts:
            current_user.favorite_scripts.append(script)
            db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/favorites/remove', methods=['POST'])
@login_required
def api_remove_favorite():
    data = request.get_json()
    script_id = data.get('script_id')
    
    if not script_id:
        return jsonify({'status': 'error', 'message': 'Script ID gerekli'})
    
    try:
        script = get_or_404(Script, script_id)
        if script in current_user.favorite_scripts:
            current_user.favorite_scripts.remove(script)
            db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# Sunucu grupları ile ilgili tüm route, fonksiyon ve kullanımları kaldırıyorum

if __name__ == '__main__':
    if not os.path.exists('instance'):
        os.makedirs('instance')
    with app.app_context():
        db.create_all()
        
        # İlk admin kullanıcısını oluştur (eğer hiç kullanıcı yoksa)
        if not User.query.first():
            admin_user = User(
                username='admin',
                email='admin@example.com',
                role='admin',
                is_active=True,
                created_at=datetime.now()
            )
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            db.session.commit()
            print("✅ İlk admin kullanıcısı oluşturuldu!")
            print("👤 Kullanıcı Adı: admin")
            print("🔑 Şifre: admin123")
            print("⚠️  Güvenlik için şifreyi değiştirin!")
    app.run(debug=True, host='0.0.0.0', port=80)