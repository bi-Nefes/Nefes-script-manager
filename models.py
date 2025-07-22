from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    role = db.Column(db.String(20), nullable=False, default='user')  # admin, manager, user, viewer
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    profile_photo = db.Column(db.String(255), nullable=True)  # Profil fotoğrafı dosya yolu
    favorite_scripts = db.relationship('Script', secondary='user_favorites', backref='favorited_by')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def has_role(self, role):
        """Kullanıcının belirli bir role sahip olup olmadığını kontrol eder"""
        return self.role == role
    
    def has_permission(self, permission):
        """Kullanıcının belirli bir izne sahip olup olmadığını kontrol eder"""
        permissions = {
            'admin': ['all'],
            'manager': ['view_dashboard', 'view_servers', 'view_scripts', 'view_logs', 'view_scheduler', 
                       'add_server', 'edit_server', 'delete_server', 'add_script', 'edit_script', 
                       'delete_script', 'run_script', 'add_scheduled_task', 'edit_scheduled_task', 
                       'delete_scheduled_task', 'run_scheduled_task', 'delete_log'],
            'user': ['view_dashboard', 'view_servers', 'view_scripts', 'view_logs', 'view_scheduler', 
                    'run_script', 'add_scheduled_task', 'edit_scheduled_task', 'run_scheduled_task'],
            'viewer': ['view_dashboard', 'view_servers', 'view_scripts', 'view_logs', 'view_scheduler']
        }
        
        user_permissions = permissions.get(self.role, [])
        return 'all' in user_permissions or permission in user_permissions
    
    @property
    def role_display_name(self):
        """Rolün görüntüleme adını döndürür"""
        role_names = {
            'admin': 'Yönetici',
            'manager': 'Müdür',
            'user': 'Kullanıcı',
            'viewer': 'Görüntüleyici'
        }
        return role_names.get(self.role, self.role)
    
    @property
    def role_color(self):
        """Rolün renk kodunu döndürür"""
        role_colors = {
            'admin': 'danger',
            'manager': 'warning',
            'user': 'primary',
            'viewer': 'secondary'
        }
        return role_colors.get(self.role, 'secondary')

class Server(db.Model):
    __tablename__ = 'servers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    host = db.Column(db.String(100), nullable=False)
    port = db.Column(db.Integer, nullable=False, default=22)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)  # Düz metin olarak saklanacak
    os_type = db.Column(db.String(50), default='windows')  # 'linux' veya 'windows'
    # Sunucu grupları ile ilgili ilişki kaldırıldı

# ServerGroup ve ServerGroupMember modellerini kaldırıyorum

class Script(db.Model):
    __tablename__ = 'scripts'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    command = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)
    script_type = db.Column(db.String(20), nullable=False, default='shell')  # shell, bash, powershell, python, etc.
    is_favorite = db.Column(db.Boolean, default=False)
    usage_count = db.Column(db.Integer, default=0)
    last_used = db.Column(db.DateTime)
    # Gelişmiş görev yönetimi için yeni alanlar
    supports_parameters = db.Column(db.Boolean, default=False)
    supports_multi_target = db.Column(db.Boolean, default=False)
    can_be_chained = db.Column(db.Boolean, default=False)
    parameters = db.relationship('ScriptParameter', backref='script', cascade='all, delete-orphan')

class ScriptParameter(db.Model):
    """Script parametreleri için model"""
    __tablename__ = 'script_parameters'
    id = db.Column(db.Integer, primary_key=True)
    script_id = db.Column(db.Integer, db.ForeignKey('scripts.id'), nullable=False)
    name = db.Column(db.String(50), nullable=False)  # Parametre adı
    display_name = db.Column(db.String(100), nullable=False)  # Görüntüleme adı
    parameter_type = db.Column(db.String(20), nullable=False, default='text')  # text, number, select, file, directory
    default_value = db.Column(db.String(200))  # Varsayılan değer
    required = db.Column(db.Boolean, default=False)  # Zorunlu mu?
    options = db.Column(db.Text)  # Select tipi için seçenekler (JSON)
    placeholder = db.Column(db.String(200))  # Placeholder metni
    order_index = db.Column(db.Integer, default=0)  # Sıralama

class TaskChain(db.Model):
    """Zincirleme görevler için model"""
    __tablename__ = 'task_chains'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    # Zincirleme görevler
    tasks = db.relationship('TaskChainItem', backref='chain', cascade='all, delete-orphan', order_by='TaskChainItem.order_index')

class TaskChainItem(db.Model):
    """Zincirleme görev öğeleri"""
    __tablename__ = 'task_chain_items'
    id = db.Column(db.Integer, primary_key=True)
    chain_id = db.Column(db.Integer, db.ForeignKey('task_chains.id'), nullable=False)
    script_id = db.Column(db.Integer, db.ForeignKey('scripts.id'), nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    order_index = db.Column(db.Integer, nullable=False)  # Sıralama
    wait_for_success = db.Column(db.Boolean, default=True)  # Başarılı olursa devam et
    parameters = db.Column(db.Text)  # JSON formatında parametreler
    script = db.relationship('Script')
    server = db.relationship('Server')

class MultiTargetTask(db.Model):
    """Çoklu hedef görevler için model"""
    __tablename__ = 'multi_target_tasks'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    script_id = db.Column(db.Integer, db.ForeignKey('scripts.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    parameters = db.Column(db.Text)  # JSON formatında parametreler
    script = db.relationship('Script')

class MultiTargetTaskServer(db.Model):
    """Çoklu hedef görev sunucuları"""
    __tablename__ = 'multi_target_task_servers'
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('multi_target_tasks.id'), nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    task = db.relationship('MultiTargetTask', backref='target_servers')
    server = db.relationship('Server')

class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'))
    script_id = db.Column(db.Integer, db.ForeignKey('scripts.id'))
    output = db.Column(db.Text)
    status = db.Column(db.String(20))  # success / error
    # Gelişmiş görev yönetimi için yeni alanlar
    execution_type = db.Column(db.String(20), default='single')  # single, parallel, sequential, conditional, chain, multi_target
    chain_id = db.Column(db.Integer, db.ForeignKey('task_chains.id'), nullable=True)
    multi_target_task_id = db.Column(db.Integer, db.ForeignKey('multi_target_tasks.id'), nullable=True)
    parameters_used = db.Column(db.Text)  # JSON formatında kullanılan parametreler
    execution_time = db.Column(db.Float)  # Çalışma süresi (saniye)
    server = db.relationship('Server', backref='logs')
    script = db.relationship('Script', backref='logs')

class ScheduledTask(db.Model):
    __tablename__ = 'scheduled_tasks'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    script_id = db.Column(db.Integer, db.ForeignKey('scripts.id'), nullable=False)
    cron_expression = db.Column(db.String(100), nullable=False)  # "0 9 * * 1" (her pazartesi saat 9)
    is_active = db.Column(db.Boolean, default=True)
    last_run = db.Column(db.DateTime)
    next_run = db.Column(db.DateTime)
    # Gelişmiş görev yönetimi için yeni alanlar
    execution_type = db.Column(db.String(20), default='single')  # single, chain, multi_target
    chain_id = db.Column(db.Integer, db.ForeignKey('task_chains.id'), nullable=True)
    multi_target_task_id = db.Column(db.Integer, db.ForeignKey('multi_target_tasks.id'), nullable=True)
    parameters = db.Column(db.Text)  # JSON formatında parametreler
    server = db.relationship('Server', backref='scheduled_tasks')
    script = db.relationship('Script', backref='scheduled_tasks')

# Kullanıcı favori scriptleri için ara tablo
user_favorites = db.Table('user_favorites',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('script_id', db.Integer, db.ForeignKey('scripts.id'), primary_key=True),
    db.Column('added_at', db.DateTime, default=datetime.utcnow)
) 