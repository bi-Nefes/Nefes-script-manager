import os
os.environ["FLASK_SKIP_DOTENV"] = "1"
from flask import Flask, render_template, redirect, url_for, request, session, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import db, User, Server, ServerGroup, ServerGroupMember, Script, Log, ScheduledTask, DeviceType, ConfigBackup, NetworkInterface, DeviceMonitoring
import paramiko
from sqlalchemy import or_
from datetime import datetime, timedelta
import croniter
from functools import wraps
import hashlib
import re
import json
import qrcode
import io
import base64

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
            
            # MFA kontrolü
            if user.mfa_enabled:
                # MFA doğrulama sayfasına yönlendir
                session['temp_user_id'] = user.id
                session['temp_username'] = user.username
                return redirect(url_for('mfa_verify'))
            else:
                # MFA kurulum sayfasına yönlendir
                session['temp_user_id'] = user.id
                session['temp_username'] = user.username
                return redirect(url_for('mfa_setup'))
        else:
            flash('Kullanıcı adı veya şifre hatalı!', 'error')
    return render_template('login.html')

@app.route('/mfa-setup', methods=['GET', 'POST'])
def mfa_setup():
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['temp_user_id'])
    if not user:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # MFA kurulumunu tamamla
        user.complete_mfa_setup()
        db.session.commit()
        
        # Kullanıcıyı giriş yap
        login_user(user)
        user.last_login = datetime.now()
        db.session.commit()
        
        # Session'ı temizle
        session.pop('temp_user_id', None)
        session.pop('temp_username', None)
        
        flash(f'Hoş geldiniz, {user.username}! MFA başarıyla kuruldu.', 'success')
        return redirect(url_for('dashboard'))
    
    # MFA kurulumu için secret key oluştur
    if not user.mfa_secret:
        secret, backup_codes = user.setup_mfa()
        db.session.commit()
    else:
        secret = user.mfa_secret
        backup_codes = json.loads(user.mfa_backup_codes) if user.mfa_backup_codes else []
    
    # QR kod oluştur
    qr_uri = user.get_mfa_qr_code_data()
    if qr_uri:
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Base64'e çevir
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
    else:
        qr_code_base64 = None
    
    return render_template('mfa_setup.html', user=user, secret=secret, backup_codes=backup_codes, qr_code_base64=qr_code_base64)

@app.route('/mfa-verify', methods=['GET', 'POST'])
def mfa_verify():
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['temp_user_id'])
    if not user:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        backup_code = request.form.get('backup_code', '').strip()
        
        if token:
            # TOTP token doğrulama
            if user.verify_totp(token):
                # Başarılı giriş
                login_user(user)
                user.last_login = datetime.now()
                db.session.commit()
                
                # Session'ı temizle
                session.pop('temp_user_id', None)
                session.pop('temp_username', None)
                
                flash(f'Hoş geldiniz, {user.username}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Geçersiz doğrulama kodu!', 'error')
        elif backup_code:
            # Yedek kod doğrulama
            if user.verify_backup_code(backup_code):
                db.session.commit()
                
                # Başarılı giriş
                login_user(user)
                user.last_login = datetime.now()
                db.session.commit()
                
                # Session'ı temizle
                session.pop('temp_user_id', None)
                session.pop('temp_username', None)
                
                flash(f'Hoş geldiniz, {user.username}! Yedek kod ile giriş yapıldı.', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Geçersiz yedek kod!', 'error')
        else:
            flash('Lütfen doğrulama kodu veya yedek kod girin!', 'error')
    
    return render_template('mfa_verify.html', user=user)

@app.route('/mfa-disable', methods=['POST'])
@login_required
def mfa_disable():
    if request.method == 'POST':
        current_user.mfa_enabled = False
        current_user.mfa_secret = None
        current_user.mfa_backup_codes = None
        current_user.mfa_setup_completed = False
        db.session.commit()
        flash('MFA başarıyla devre dışı bırakıldı!', 'success')
    return redirect(url_for('profile'))

@app.route('/mfa-reset', methods=['POST'])
@login_required
def mfa_reset():
    if request.method == 'POST':
        # Yeni MFA kurulumu
        secret, backup_codes = current_user.setup_mfa()
        current_user.mfa_setup_completed = False
        db.session.commit()
        flash('MFA başarıyla sıfırlandı! Yeni QR kodu ile kurulum yapın.', 'success')
    return redirect(url_for('profile'))

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
                         datetime=datetime,
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
        
        # Network cihazı özellikleri
        is_network_device = 'is_network_device' in request.form
        device_type_id = request.form.get('device_type_id')
        device_model = request.form.get('device_model')
        serial_number = request.form.get('serial_number')
        firmware_version = request.form.get('firmware_version')
        location = request.form.get('location')
        rack_position = request.form.get('rack_position')
        management_ip = request.form.get('management_ip')
        
        new_server = Server(
            name=name, host=host, port=port, username=username, password=password,
            is_network_device=is_network_device,
            device_type_id=device_type_id if device_type_id else None,
            device_model=device_model,
            serial_number=serial_number,
            firmware_version=firmware_version,
            location=location,
            rack_position=rack_position,
            management_ip=management_ip
        )
        db.session.add(new_server)
        db.session.commit()
        flash('Sunucu eklendi!', 'success')
        return redirect(url_for('servers'))
    
    device_types = DeviceType.query.filter_by(is_active=True).all()
    return render_template('server_form.html', action='add', device_types=device_types)

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
        
        # Network cihazı özellikleri
        server.is_network_device = 'is_network_device' in request.form
        server.device_type_id = request.form.get('device_type_id') if request.form.get('device_type_id') else None
        server.device_model = request.form.get('device_model')
        server.serial_number = request.form.get('serial_number')
        server.firmware_version = request.form.get('firmware_version')
        server.location = request.form.get('location')
        server.rack_position = request.form.get('rack_position')
        server.management_ip = request.form.get('management_ip')
        
        db.session.commit()
        flash('Sunucu güncellendi!', 'success')
        return redirect(url_for('servers'))
    
    device_types = DeviceType.query.filter_by(is_active=True).all()
    return render_template('server_form.html', action='edit', server=server, device_types=device_types)

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
        
        # Yeni alanlar
        wait_for_output = 'wait_for_output' in request.form
        is_long_running = 'is_long_running' in request.form
        default_timeout = int(request.form.get('default_timeout', 60))
        
        new_script = Script(
            name=name, 
            command=command, 
            description=description, 
            script_type=script_type,
            wait_for_output=wait_for_output,
            is_long_running=is_long_running,
            default_timeout=default_timeout
        )
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
        
        # Yeni alanlar
        script.wait_for_output = 'wait_for_output' in request.form
        script.is_long_running = 'is_long_running' in request.form
        script.default_timeout = int(request.form.get('default_timeout', 60))
        
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
    server_groups = ServerGroup.query.filter_by(is_active=True).all()
    outputs = []  # Her sunucu için çıktı ve durum
    selected_servers = []
    selected_scripts = []
    
    if request.method == 'POST':
        server_ids = request.form.getlist('server_id')
        script_ids = request.form.getlist('script_ids')
        # execution_mode kaldırıldı
        
        if not script_ids:
            flash('En az bir script seçmelisiniz!', 'error')
            return render_template('run_script.html', servers=servers, scripts=scripts)
        
        if not server_ids:
            flash('En az bir sunucu seçmelisiniz!', 'error')
            return render_template('run_script.html', servers=servers, scripts=scripts)
        
        # Scriptleri ve sunucuları al
        selected_scripts = [db.session.get(Script, sid) for sid in script_ids]
        selected_servers = [db.session.get(Server, sid) for sid in server_ids]
        
        # Her zaman sıralı modda çalıştır
        outputs = execute_scripts_sequential(selected_scripts, selected_servers)
    
    return render_template('run_script.html', servers=servers, scripts=scripts, server_groups=server_groups, outputs=outputs, selected_servers=selected_servers, selected_scripts=selected_scripts)

def execute_scripts_parallel(scripts, servers, timeout=60):
    """Scriptleri paralel olarak çalıştır"""
    import threading
    import queue
    import time
    import sys
    
    outputs = []
    output_queue = queue.Queue()
    completed_tasks = 0
    total_tasks = len(scripts) * len(servers)
    
    def run_script_on_server(script, server):
        nonlocal completed_tasks
        output = ''
        status = 'success'
        start_time = time.time()
        execution_time = 0
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(server.host, port=server.port, username=server.username, password=server.password, timeout=30)
            # Script türüne göre komut hazırla
            command = prepare_command(script)
            stdin, stdout, stderr = ssh.exec_command(command)
            
            # Script'in çıktı bekleme ayarına göre davranış
            if script.wait_for_output:
                # Timeout ile çıktı okuma
                output_data = {'stdout': '', 'stderr': '', 'completed': False}
                
                def read_output():
                    try:
                        output_data['stdout'] = stdout.read().decode('utf-8', errors='replace')
                        output_data['completed'] = True
                    except Exception as e:
                        output_data['stdout'] = f"Çıktı okuma hatası: {str(e)}"
                        output_data['completed'] = True
                
                def read_error():
                    try:
                        output_data['stderr'] = stderr.read().decode('utf-8', errors='replace')
                    except Exception as e:
                        output_data['stderr'] = f"Hata çıktısı okuma hatası: {str(e)}"
                
                # Thread'ler ile çıktı okuma
                stdout_thread = threading.Thread(target=read_output)
                stderr_thread = threading.Thread(target=read_error)
                
                stdout_thread.start()
                stderr_thread.start()
                
                # Timeout bekle
                stdout_thread.join(timeout=timeout)
                stderr_thread.join(timeout=timeout)
                
                # Eğer timeout olduysa
                if not output_data['completed']:
                    output_data['stdout'] += f"\n[TIMEOUT] Komut {timeout} saniye sonra sonlandırıldı."
                    status = 'timeout'
                    # SSH bağlantısını kapat
                    ssh.close()
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(server.host, port=server.port, username=server.username, password=server.password, timeout=30)
                    # Çalışan komutu sonlandır
                    ssh.exec_command('pkill -f "' + command.split()[0] + '"')
            else:
                # Çıktı bekleme, sadece komutu başlat
                output_data = {'stdout': f'[STARTED] Komut başlatıldı: {command}\n[INFO] Çıktı beklenmiyor, komut arka planda çalışıyor...', 'stderr': ''}
                status = 'started'
            
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
            
            output = output_data['stdout'] + ('\n' + output_data['stderr'] if output_data['stderr'] else '')
            
            # Çıktı beklemeyen scriptler için status'u güncelle
            if not script.wait_for_output:
                status = 'started'  # Çıktı beklenmiyorsa "started" olarak işaretle
            elif output_data['stderr']:
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
        completed_tasks += 1
        # Debug: çıktıyı logla
        print(f'[DEBUG][{server.name}][{script.name}] Çıktı:', output, file=sys.stderr)
        output_queue.put({
            'server': server,
            'script': script,
            'output': output,
            'status': status,
            'execution_time': execution_time
        })
    
    threads = []
    for script in scripts:
        for server in servers:
            thread = threading.Thread(target=run_script_on_server, args=(script, server))
            threads.append(thread)
            thread.start()
    for thread in threads:
        thread.join()
    while not output_queue.empty():
        outputs.append(output_queue.get())
    db.session.commit()
    return outputs

def execute_scripts_sequential(scripts, servers, timeout=60):
    """Scriptleri sıralı olarak çalıştır"""
    import time
    import threading
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
                
                # Komutun çıktısını timeout ile çalıştır
                stdin, stdout, stderr = ssh.exec_command(command)
                
                # Script'in çıktı bekleme ayarına göre davranış
                if script.wait_for_output:
                    # Timeout ile çıktı okuma
                    output_data = {'stdout': '', 'stderr': '', 'completed': False}
                    
                    def read_output():
                        try:
                            output_data['stdout'] = stdout.read().decode('utf-8', errors='replace')
                            output_data['completed'] = True
                        except Exception as e:
                            output_data['stdout'] = f"Çıktı okuma hatası: {str(e)}"
                            output_data['completed'] = True
                    
                    def read_error():
                        try:
                            output_data['stderr'] = stderr.read().decode('utf-8', errors='replace')
                        except Exception as e:
                            output_data['stderr'] = f"Hata çıktısı okuma hatası: {str(e)}"
                    
                    # Thread'ler ile çıktı okuma
                    stdout_thread = threading.Thread(target=read_output)
                    stderr_thread = threading.Thread(target=read_error)
                    
                    stdout_thread.start()
                    stderr_thread.start()
                    
                    # Timeout bekle
                    stdout_thread.join(timeout=timeout)
                    stderr_thread.join(timeout=timeout)
                    
                    # Eğer timeout olduysa
                    if not output_data['completed']:
                        output_data['stdout'] += f"\n[TIMEOUT] Komut {timeout} saniye sonra sonlandırıldı."
                        status = 'timeout'
                        # SSH bağlantısını kapat
                        ssh.close()
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(server.host, port=server.port, username=server.username, password=server.password, timeout=30)
                        # Çalışan komutu sonlandır
                        ssh.exec_command('pkill -f "' + command.split()[0] + '"')
                else:
                    # Çıktı bekleme, sadece komutu başlat
                    output_data = {'stdout': f'[STARTED] Komut başlatıldı: {command}\n[INFO] Çıktı beklenmiyor, komut arka planda çalışıyor...', 'stderr': ''}
                    status = 'started'
                
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
                
                output = output_data['stdout'] + ('\n' + output_data['stderr'] if output_data['stderr'] else '')
                
                # Çıktı beklemeyen scriptler için status'u güncelle
                if not script.wait_for_output:
                    status = 'started'  # Çıktı beklenmiyorsa "started" olarak işaretle
                elif output_data['stderr']:
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

def execute_scripts_conditional(scripts, servers, timeout=60):
    """Scriptleri koşullu olarak çalıştır (başarılı olursa devam et)"""
    import time
    import threading
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
                
                # Komutun çıktısını timeout ile çalıştır
                stdin, stdout, stderr = ssh.exec_command(command)
                
                # Script'in çıktı bekleme ayarına göre davranış
                if script.wait_for_output:
                    # Timeout ile çıktı okuma
                    output_data = {'stdout': '', 'stderr': '', 'completed': False}
                    
                    def read_output():
                        try:
                            output_data['stdout'] = stdout.read().decode('utf-8', errors='replace')
                            output_data['completed'] = True
                        except Exception as e:
                            output_data['stdout'] = f"Çıktı okuma hatası: {str(e)}"
                            output_data['completed'] = True
                    
                    def read_error():
                        try:
                            output_data['stderr'] = stderr.read().decode('utf-8', errors='replace')
                        except Exception as e:
                            output_data['stderr'] = f"Hata çıktısı okuma hatası: {str(e)}"
                    
                    # Thread'ler ile çıktı okuma
                    stdout_thread = threading.Thread(target=read_output)
                    stderr_thread = threading.Thread(target=read_error)
                    
                    stdout_thread.start()
                    stderr_thread.start()
                    
                    # Timeout bekle
                    stdout_thread.join(timeout=timeout)
                    stderr_thread.join(timeout=timeout)
                    
                    # Eğer timeout olduysa
                    if not output_data['completed']:
                        output_data['stdout'] += f"\n[TIMEOUT] Komut {timeout} saniye sonra sonlandırıldı."
                        status = 'timeout'
                        script_success = False
                        # SSH bağlantısını kapat
                        ssh.close()
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(server.host, port=server.port, username=server.username, password=server.password, timeout=30)
                        # Çalışan komutu sonlandır
                        ssh.exec_command('pkill -f "' + command.split()[0] + '"')
                else:
                    # Çıktı bekleme, sadece komutu başlat
                    output_data = {'stdout': f'[STARTED] Komut başlatıldı: {command}\n[INFO] Çıktı beklenmiyor, komut arka planda çalışıyor...', 'stderr': ''}
                    status = 'started'
                
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
                
                output = output_data['stdout'] + ('\n' + output_data['stderr'] if output_data['stderr'] else '')
                
                # Çıktı beklemeyen scriptler için status'u güncelle
                if not script.wait_for_output:
                    status = 'started'  # Çıktı beklenmiyorsa "started" olarak işaretle
                elif output_data['stderr']:
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
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    query = Log.query
    
    if server_id:
        query = query.filter(Log.server_id == server_id)
    if script_id:
        query = query.filter(Log.script_id == script_id)
    if start_date:
        try:
            start_datetime = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(Log.timestamp >= start_datetime)
        except ValueError:
            pass
    if end_date:
        try:
            end_datetime = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(Log.timestamp < end_datetime)
        except ValueError:
            pass
    
    logs = query.order_by(Log.timestamp.desc()).all()
    return render_template('logs.html', logs=logs, servers=servers, scripts=scripts, 
                         selected_server=server_id, selected_script=script_id, 
                         start_date=start_date, end_date=end_date, timedelta=timedelta)

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
        
        # Status değişkenini tanımla
        status = 'success'
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

@app.route('/api/run-scripts', methods=['POST'])
@login_required
@permission_required('run_script')
def api_run_scripts():
    data = request.get_json()
    server_ids = data.get('server_ids', [])
    script_ids = data.get('script_ids', [])
    
    if not script_ids:
        return {'status': 'error', 'message': 'En az bir script seçmelisiniz!'}, 400
    if not server_ids:
        return {'status': 'error', 'message': 'En az bir sunucu seçmelisiniz!'}, 400
    
    selected_scripts = [db.session.get(Script, sid) for sid in script_ids]
    selected_servers = [db.session.get(Server, sid) for sid in server_ids]
    
    # Her script için kendi timeout değerini kullan
    outputs = []
    for script in selected_scripts:
        script_outputs = execute_scripts_sequential([script], selected_servers, timeout=script.default_timeout)
        outputs.extend(script_outputs)
    # JSON serializable hale getir
    def serialize_output(item):
        return {
            'server': {'id': item['server'].id, 'name': item['server'].name, 'host': item['server'].host},
            'script': {'id': item['script'].id, 'name': item['script'].name},
            'status': item['status'],
            'output': item['output'],
            'execution_time': item.get('execution_time')
        }
    return {'status': 'success', 'outputs': [serialize_output(item) for item in outputs]}

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

@app.route('/api/server-groups/<int:group_id>/servers')
@login_required
@permission_required('view_servers')
def api_server_group_servers(group_id):
    """Sunucu grubundaki sunucuları döndür"""
    group = get_or_404(ServerGroup, group_id)
    members = ServerGroupMember.query.filter_by(group_id=group_id).all()
    
    servers = []
    for member in members:
        server = member.server
        if server:  # Eğer sunucu hala mevcut ise
            servers.append({
                'id': server.id,
                'name': server.name,
                'host': server.host,
                'port': server.port
            })
    
    return jsonify({
        'status': 'success',
        'group_name': group.name,
        'servers': servers
    })

# Sunucu Grupları Route'ları
@app.route('/server-groups')
@login_required
@permission_required('view_servers')
def server_groups():
    groups = ServerGroup.query.filter_by(is_active=True).all()
    return render_template('server_groups.html', groups=groups)

@app.route('/server-groups/add', methods=['GET', 'POST'])
@login_required
@permission_required('add_server')
def add_server_group():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        color = request.form.get('color', 'primary')
        icon = request.form.get('icon', 'fa-layer-group')
        
        if not name:
            flash('Grup adı gerekli!', 'error')
            return redirect(url_for('add_server_group'))
        
        group = ServerGroup(
            name=name, 
            description=description, 
            created_by=current_user.id,
            color=color,
            icon=icon
        )
        db.session.add(group)
        db.session.commit()
        flash('Sunucu grubu başarıyla oluşturuldu!', 'success')
        return redirect(url_for('server_groups'))
    
    return render_template('server_group_form.html')

@app.route('/server-groups/edit/<int:group_id>', methods=['GET', 'POST'])
@login_required
@permission_required('edit_server')
def edit_server_group(group_id):
    group = get_or_404(ServerGroup, group_id)
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        color = request.form.get('color', 'primary')
        icon = request.form.get('icon', 'fa-layer-group')
        
        if not name:
            flash('Grup adı gerekli!', 'error')
            return redirect(url_for('edit_server_group', group_id=group_id))
        
        group.name = name
        group.description = description
        group.color = color
        group.icon = icon
        db.session.commit()
        flash('Sunucu grubu başarıyla güncellendi!', 'success')
        return redirect(url_for('server_groups'))
    
    return render_template('server_group_form.html', group=group)

@app.route('/server-groups/delete/<int:group_id>', methods=['POST'])
@login_required
@permission_required('delete_server')
def delete_server_group(group_id):
    group = get_or_404(ServerGroup, group_id)
    group.is_active = False
    db.session.commit()
    flash('Sunucu grubu başarıyla silindi!', 'success')
    return redirect(url_for('server_groups'))

@app.route('/server-groups/<int:group_id>/members')
@login_required
@permission_required('view_servers')
def server_group_members(group_id):
    group = get_or_404(ServerGroup, group_id)
    members = ServerGroupMember.query.filter_by(group_id=group_id).all()
    available_servers = Server.query.filter(~Server.id.in_([m.server_id for m in members])).all()
    return render_template('server_group_members.html', group=group, members=members, available_servers=available_servers)

@app.route('/server-groups/<int:group_id>/add-member', methods=['POST'])
@login_required
@permission_required('edit_server')
def add_server_to_group(group_id):
    group = get_or_404(ServerGroup, group_id)
    server_id = request.form.get('server_id')
    
    if not server_id:
        flash('Sunucu seçilmedi!', 'error')
        return redirect(url_for('server_group_members', group_id=group_id))
    
    # Zaten üye mi kontrol et
    existing_member = ServerGroupMember.query.filter_by(group_id=group_id, server_id=server_id).first()
    if existing_member:
        flash('Bu sunucu zaten grupta!', 'error')
        return redirect(url_for('server_group_members', group_id=group_id))
    
    member = ServerGroupMember(
        group_id=group_id,
        server_id=server_id,
        added_by=current_user.id
    )
    db.session.add(member)
    db.session.commit()
    flash('Sunucu gruba başarıyla eklendi!', 'success')
    return redirect(url_for('server_group_members', group_id=group_id))

@app.route('/server-groups/<int:group_id>/remove-member/<int:server_id>', methods=['POST'])
@login_required
@permission_required('edit_server')
def remove_server_from_group(group_id, server_id):
    member = ServerGroupMember.query.filter_by(group_id=group_id, server_id=server_id).first()
    if member:
        db.session.delete(member)
        db.session.commit()
        flash('Sunucu gruptan başarıyla çıkarıldı!', 'success')
    return redirect(url_for('server_group_members', group_id=group_id))

# Network Cihazları Route'ları
@app.route('/device-types')
@login_required
@permission_required('view_servers')
def device_types():
    device_types = DeviceType.query.filter_by(is_active=True).all()
    return render_template('device_types.html', device_types=device_types)

@app.route('/device-types/add', methods=['GET', 'POST'])
@login_required
@permission_required('add_server')
def add_device_type():
    if request.method == 'POST':
        name = request.form.get('name')
        vendor = request.form.get('vendor')
        model_family = request.form.get('model_family')
        description = request.form.get('description')
        show_config_cmd = request.form.get('show_config_cmd', 'show running-config')
        show_interfaces_cmd = request.form.get('show_interfaces_cmd', 'show interfaces')
        show_version_cmd = request.form.get('show_version_cmd', 'show version')
        show_uptime_cmd = request.form.get('show_uptime_cmd', 'show uptime')
        extra_commands = request.form.get('extra_commands')
        
        if not name or not vendor:
            flash('Cihaz türü adı ve vendor bilgisi gerekli!', 'error')
            return redirect(url_for('add_device_type'))
        
        device_type = DeviceType(
            name=name,
            vendor=vendor,
            model_family=model_family,
            description=description,
            show_config_cmd=show_config_cmd,
            show_interfaces_cmd=show_interfaces_cmd,
            show_version_cmd=show_version_cmd,
            show_uptime_cmd=show_uptime_cmd,
            extra_commands=extra_commands
        )
        db.session.add(device_type)
        db.session.commit()
        flash('Cihaz türü başarıyla eklendi!', 'success')
        return redirect(url_for('device_types'))
    
    return render_template('device_type_form.html', action='add')

@app.route('/device-types/edit/<int:type_id>', methods=['GET', 'POST'])
@login_required
@permission_required('edit_server')
def edit_device_type(type_id):
    device_type = get_or_404(DeviceType, type_id)
    
    if request.method == 'POST':
        device_type.name = request.form.get('name')
        device_type.vendor = request.form.get('vendor')
        device_type.model_family = request.form.get('model_family')
        device_type.description = request.form.get('description')
        device_type.show_config_cmd = request.form.get('show_config_cmd', 'show running-config')
        device_type.show_interfaces_cmd = request.form.get('show_interfaces_cmd', 'show interfaces')
        device_type.show_version_cmd = request.form.get('show_version_cmd', 'show version')
        device_type.show_uptime_cmd = request.form.get('show_uptime_cmd', 'show uptime')
        device_type.extra_commands = request.form.get('extra_commands')
        db.session.commit()
        flash('Cihaz türü başarıyla güncellendi!', 'success')
        return redirect(url_for('device_types'))
    
    return render_template('device_type_form.html', action='edit', device_type=device_type)

@app.route('/device-types/delete/<int:type_id>', methods=['POST'])
@login_required
@permission_required('delete_server')
def delete_device_type(type_id):
    device_type = get_or_404(DeviceType, type_id)
    device_type.is_active = False
    db.session.commit()
    flash('Cihaz türü başarıyla silindi!', 'success')
    return redirect(url_for('device_types'))

# Config Backup Route'ları
@app.route('/config-backups')
@login_required
@permission_required('view_servers')
def config_backups():
    device_id = request.args.get('device_id', type=int)
    if device_id:
        backups = ConfigBackup.query.filter_by(device_id=device_id).order_by(ConfigBackup.created_at.desc()).all()
        device = get_or_404(Server, device_id)
    else:
        backups = ConfigBackup.query.order_by(ConfigBackup.created_at.desc()).limit(50).all()
        device = None
    
    devices = Server.query.filter_by(is_network_device=True).all()
    return render_template('config_backups.html', backups=backups, devices=devices, selected_device=device)

@app.route('/config-backups/create/<int:device_id>', methods=['POST'])
@login_required
@permission_required('run_script')
def create_config_backup(device_id):
    device = get_or_404(Server, device_id)
    
    if not device.is_network_device:
        flash('Bu cihaz network cihazı değil!', 'error')
        return redirect(url_for('config_backups'))
    
    try:
        # SSH bağlantısı
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(device.host, port=device.port, username=device.username, 
                   password=device.password, timeout=30)
        
        # Config komutunu al
        config_cmd = 'show running-config'
        if device.device_type_info:
            config_cmd = device.device_type_info.show_config_cmd
        
        # Config'i çek
        stdin, stdout, stderr = ssh.exec_command(config_cmd)
        config_content = stdout.read().decode('utf-8', errors='replace')
        ssh.close()
        
        if not config_content.strip():
            flash('Config içeriği alınamadı!', 'error')
            return redirect(url_for('config_backups'))
        
        # Hash oluştur
        config_hash = hashlib.sha256(config_content.encode()).hexdigest()
        
        # Backup adı oluştur
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"{device.name}_config_{timestamp}"
        
        # Backup kaydet
        backup = ConfigBackup(
            device_id=device.id,
            backup_name=backup_name,
            config_content=config_content,
            config_hash=config_hash,
            backup_type='manual',
            description=request.form.get('description', 'Manuel backup'),
            created_by=current_user.id,
            file_size=len(config_content.encode())
        )
        db.session.add(backup)
        
        # Cihazın son backup zamanını güncelle
        device.last_config_backup = datetime.now()
        db.session.commit()
        
        flash(f'{device.name} cihazının config backup\'ı başarıyla oluşturuldu!', 'success')
        
    except Exception as e:
        flash(f'Config backup oluşturulurken hata: {str(e)}', 'error')
    
    return redirect(url_for('config_backups', device_id=device_id))

@app.route('/config-backups/compare/<int:backup1_id>/<int:backup2_id>')
@login_required
@permission_required('view_servers')
def compare_config_backups(backup1_id, backup2_id):
    backup1 = get_or_404(ConfigBackup, backup1_id)
    backup2 = get_or_404(ConfigBackup, backup2_id)
    
    # Basit diff oluştur
    lines1 = backup1.config_content.split('\n')
    lines2 = backup2.config_content.split('\n')
    
    diff_result = []
    for i, (line1, line2) in enumerate(zip(lines1, lines2), 1):
        if line1 != line2:
            diff_result.append({
                'line_number': i,
                'old_line': line1,
                'new_line': line2
            })
    
    # Farklı uzunluklar için
    if len(lines1) > len(lines2):
        for i in range(len(lines2), len(lines1)):
            diff_result.append({
                'line_number': i + 1,
                'old_line': lines1[i],
                'new_line': ''
            })
    elif len(lines2) > len(lines1):
        for i in range(len(lines1), len(lines2)):
            diff_result.append({
                'line_number': i + 1,
                'old_line': '',
                'new_line': lines2[i]
            })
    
    return render_template('config_compare.html', backup1=backup1, backup2=backup2, diff_result=diff_result)

@app.route('/config-backups/download/<int:backup_id>')
@login_required
@permission_required('view_servers')
def download_config_backup(backup_id):
    backup = get_or_404(ConfigBackup, backup_id)
    
    from flask import send_file
    import tempfile
    import os
    
    # Geçici dosya oluştur
    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.cfg')
    temp_file.write(backup.config_content)
    temp_file.close()
    
    return send_file(temp_file.name, as_attachment=True, 
                    download_name=f"{backup.backup_name}.cfg",
                    mimetype='text/plain')

# Network Monitoring Route'ları
@app.route('/network-monitoring')
@login_required
@permission_required('view_servers')
def network_monitoring():
    device_id = request.args.get('device_id', type=int)
    if device_id:
        device = get_or_404(Server, device_id)
        monitoring_data = DeviceMonitoring.query.filter_by(device_id=device_id).order_by(DeviceMonitoring.timestamp.desc()).limit(100).all()
        interfaces = NetworkInterface.query.filter_by(device_id=device_id).all()
    else:
        device = None
        monitoring_data = []
        interfaces = []
    
    devices = Server.query.filter_by(is_network_device=True).all()
    return render_template('network_monitoring.html', device=device, devices=devices, 
                         monitoring_data=monitoring_data, interfaces=interfaces)

@app.route('/network-monitoring/collect/<int:device_id>', methods=['POST'])
@login_required
@permission_required('run_script')
def collect_monitoring_data(device_id):
    device = get_or_404(Server, device_id)
    
    if not device.is_network_device:
        flash('Bu cihaz network cihazı değil!', 'error')
        return redirect(url_for('network_monitoring'))
    
    try:
        # SSH bağlantısı
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(device.host, port=device.port, username=device.username, 
                   password=device.password, timeout=30)
        
        # Monitoring verilerini topla
        monitoring_data = collect_device_monitoring(ssh, device)
        
        # Veritabanına kaydet
        monitoring = DeviceMonitoring(
            device_id=device.id,
            **monitoring_data
        )
        db.session.add(monitoring)
        
        # Interface bilgilerini güncelle
        update_interface_info(ssh, device)
        
        # Cihazın son monitoring zamanını güncelle
        device.last_monitoring_check = datetime.now()
        db.session.commit()
        
        flash(f'{device.name} cihazının monitoring verileri başarıyla toplandı!', 'success')
        
    except Exception as e:
        flash(f'Monitoring verileri toplanırken hata: {str(e)}', 'error')
    
    return redirect(url_for('network_monitoring', device_id=device_id))

def collect_device_monitoring(ssh, device):
    """Cihazdan monitoring verilerini topla"""
    monitoring_data = {}
    
    try:
        # CPU kullanımı
        stdin, stdout, stderr = ssh.exec_command('show processes cpu')
        cpu_output = stdout.read().decode('utf-8', errors='replace')
        cpu_match = re.search(r'CPU utilization for five seconds: (\d+)%', cpu_output)
        if cpu_match:
            monitoring_data['cpu_usage'] = float(cpu_match.group(1))
        
        # Memory kullanımı
        stdin, stdout, stderr = ssh.exec_command('show memory statistics')
        memory_output = stdout.read().decode('utf-8', errors='replace')
        # Memory parsing logic burada...
        
        # Uptime
        stdin, stdout, stderr = ssh.exec_command('show uptime')
        uptime_output = stdout.read().decode('utf-8', errors='replace')
        uptime_match = re.search(r'uptime is (.+)', uptime_output)
        if uptime_match:
            # Uptime parsing logic burada...
            pass
        
        # Interface sayıları
        stdin, stdout, stderr = ssh.exec_command('show interfaces')
        interfaces_output = stdout.read().decode('utf-8', errors='replace')
        
        total_interfaces = len(re.findall(r'^[A-Za-z0-9/]+ is', interfaces_output, re.MULTILINE))
        up_interfaces = len(re.findall(r'^[A-Za-z0-9/]+ is up', interfaces_output, re.MULTILINE))
        down_interfaces = total_interfaces - up_interfaces
        
        monitoring_data.update({
            'total_interfaces': total_interfaces,
            'up_interfaces': up_interfaces,
            'down_interfaces': down_interfaces
        })
        
    except Exception as e:
        print(f"Monitoring veri toplama hatası: {e}")
    
    return monitoring_data

def update_interface_info(ssh, device):
    """Interface bilgilerini güncelle"""
    try:
        stdin, stdout, stderr = ssh.exec_command('show interfaces')
        interfaces_output = stdout.read().decode('utf-8', errors='replace')
        
        # Mevcut interface'leri sil
        NetworkInterface.query.filter_by(device_id=device.id).delete()
        
        # Interface'leri parse et ve kaydet
        interface_blocks = re.split(r'\n(?=[A-Za-z0-9/]+ is)', interfaces_output)
        
        for block in interface_blocks:
            if not block.strip():
                continue
                
            lines = block.strip().split('\n')
            if not lines:
                continue
                
            interface_name = lines[0].split()[0]
            
            # Interface bilgilerini parse et
            interface_data = {
                'device_id': device.id,
                'interface_name': interface_name,
                'status': 'down'
            }
            
            for line in lines:
                if 'is up' in line:
                    interface_data['status'] = 'up'
                elif 'is down' in line:
                    interface_data['status'] = 'down'
                elif 'is administratively down' in line:
                    interface_data['status'] = 'administratively down'
                elif 'Internet address is' in line:
                    ip_match = re.search(r'Internet address is ([0-9.]+)/([0-9]+)', line)
                    if ip_match:
                        interface_data['ip_address'] = ip_match.group(1)
                        interface_data['subnet_mask'] = ip_match.group(2)
                elif 'description' in line:
                    desc_match = re.search(r'description (.+)', line)
                    if desc_match:
                        interface_data['description'] = desc_match.group(1)
            
            interface = NetworkInterface(**interface_data)
            db.session.add(interface)
        
        db.session.commit()
        
    except Exception as e:
        print(f"Interface bilgileri güncelleme hatası: {e}")

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
    
        # Varsayılan cihaz türlerini ekle
        if not DeviceType.query.first():
            default_device_types = [
                {
                    'name': 'Cisco Router',
                    'vendor': 'Cisco',
                    'model_family': 'ISR/ASR',
                    'description': 'Cisco Router cihazları',
                    'show_config_cmd': 'show running-config',
                    'show_interfaces_cmd': 'show interfaces',
                    'show_version_cmd': 'show version',
                    'show_uptime_cmd': 'show uptime'
                },
                {
                    'name': 'Cisco Switch',
                    'vendor': 'Cisco',
                    'model_family': 'Catalyst/Nexus',
                    'description': 'Cisco Switch cihazları',
                    'show_config_cmd': 'show running-config',
                    'show_interfaces_cmd': 'show interfaces',
                    'show_version_cmd': 'show version',
                    'show_uptime_cmd': 'show uptime'
                },
                {
                    'name': 'Cisco Firewall',
                    'vendor': 'Cisco',
                    'model_family': 'ASA/FirePOWER',
                    'description': 'Cisco Firewall cihazları',
                    'show_config_cmd': 'show running-config',
                    'show_interfaces_cmd': 'show interface',
                    'show_version_cmd': 'show version',
                    'show_uptime_cmd': 'show uptime'
                },
                {
                    'name': 'Juniper Router',
                    'vendor': 'Juniper',
                    'model_family': 'MX/SRX',
                    'description': 'Juniper Router cihazları',
                    'show_config_cmd': 'show configuration | display-set',
                    'show_interfaces_cmd': 'show interfaces',
                    'show_version_cmd': 'show version',
                    'show_uptime_cmd': 'show system uptime'
                },
                {
                    'name': 'Juniper Switch',
                    'vendor': 'Juniper',
                    'model_family': 'EX/QFX',
                    'description': 'Juniper Switch cihazları',
                    'show_config_cmd': 'show configuration | display-set',
                    'show_interfaces_cmd': 'show interfaces',
                    'show_version_cmd': 'show version',
                    'show_uptime_cmd': 'show system uptime'
                },
                {
                    'name': 'Mikrotik Router',
                    'vendor': 'Mikrotik',
                    'model_family': 'RouterOS',
                    'description': 'Mikrotik Router cihazları',
                    'show_config_cmd': 'export',
                    'show_interfaces_cmd': 'interface print',
                    'show_version_cmd': 'system resource print',
                    'show_uptime_cmd': 'system resource print'
                },
                {
                    'name': 'HP Switch',
                    'vendor': 'HP',
                    'model_family': 'ProCurve/Aruba',
                    'description': 'HP Switch cihazları',
                    'show_config_cmd': 'show running-config',
                    'show_interfaces_cmd': 'show interfaces',
                    'show_version_cmd': 'show version',
                    'show_uptime_cmd': 'show uptime'
                },
                {
                    'name': 'Ubiquiti Device',
                    'vendor': 'Ubiquiti',
                    'model_family': 'EdgeMAX/UniFi',
                    'description': 'Ubiquiti network cihazları',
                    'show_config_cmd': 'show configuration',
                    'show_interfaces_cmd': 'show interfaces',
                    'show_version_cmd': 'show version',
                    'show_uptime_cmd': 'show system uptime'
                }
            ]
            
            for device_type_data in default_device_types:
                device_type = DeviceType(**device_type_data)
                db.session.add(device_type)
            
            db.session.commit()
            print("✅ Varsayılan cihaz türleri eklendi!")
    
    app.run(debug=False, host='0.0.0.0', port=5000)