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
    
    # MFA alanları
    mfa_secret = db.Column(db.String(32), nullable=True)  # TOTP secret key
    mfa_enabled = db.Column(db.Boolean, default=False)  # MFA aktif mi?
    mfa_backup_codes = db.Column(db.Text, nullable=True)  # JSON formatında yedek kodlar
    mfa_setup_completed = db.Column(db.Boolean, default=False)  # MFA kurulum tamamlandı mı?

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def setup_mfa(self):
        """MFA kurulumu için yeni secret key oluşturur"""
        import pyotp
        import secrets
        import json
        
        # Yeni secret key oluştur
        self.mfa_secret = pyotp.random_base32()
        self.mfa_enabled = True
        self.mfa_setup_completed = False
        
        # Yedek kodlar oluştur
        backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
        self.mfa_backup_codes = json.dumps(backup_codes)
        
        return self.mfa_secret, backup_codes
    
    def verify_totp(self, token):
        """TOTP token'ını doğrular"""
        import pyotp
        
        if not self.mfa_secret:
            return False
        
        totp = pyotp.TOTP(self.mfa_secret)
        return totp.verify(token)
    
    def verify_backup_code(self, code):
        """Yedek kodu doğrular ve kullanıldıktan sonra siler"""
        import json
        
        if not self.mfa_backup_codes:
            return False
        
        backup_codes = json.loads(self.mfa_backup_codes)
        if code.upper() in backup_codes:
            # Kullanılan kodu sil
            backup_codes.remove(code.upper())
            self.mfa_backup_codes = json.dumps(backup_codes)
            return True
        
        return False
    
    def get_mfa_qr_code_data(self):
        """MFA QR kodu için URI oluşturur"""
        import pyotp
        
        if not self.mfa_secret:
            return None
        
        totp = pyotp.TOTP(self.mfa_secret)
        return totp.provisioning_uri(
            name=self.username,
            issuer_name="Script Manager"
        )
    
    def complete_mfa_setup(self):
        """MFA kurulumunu tamamlar"""
        self.mfa_setup_completed = True
    
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

class DeviceType(db.Model):
    """Network cihaz türleri"""
    __tablename__ = 'device_types'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)  # Router, Switch, Firewall, etc.
    vendor = db.Column(db.String(50), nullable=False)  # Cisco, Juniper, Mikrotik, etc.
    model_family = db.Column(db.String(100))  # Catalyst, Nexus, etc.
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Varsayılan komutlar
    show_config_cmd = db.Column(db.String(200), default='show running-config')
    show_interfaces_cmd = db.Column(db.String(200), default='show interfaces')
    show_version_cmd = db.Column(db.String(200), default='show version')
    show_uptime_cmd = db.Column(db.String(200), default='show uptime')
    extra_commands = db.Column(db.Text)  # JSON formatında ek komutlar
    
    devices = db.relationship('Server', backref='device_type_info')

class Server(db.Model):
    __tablename__ = 'servers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    host = db.Column(db.String(100), nullable=False)
    port = db.Column(db.Integer, nullable=False, default=22)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)  # Düz metin olarak saklanacak
    os_type = db.Column(db.String(50), default='windows')  # 'linux' veya 'windows'
    
    # Network cihaz özellikleri
    device_type_id = db.Column(db.Integer, db.ForeignKey('device_types.id'), nullable=True)
    is_network_device = db.Column(db.Boolean, default=False)
    device_model = db.Column(db.String(100))  # C2960, ASR1001, etc.
    serial_number = db.Column(db.String(100))
    firmware_version = db.Column(db.String(100))
    location = db.Column(db.String(200))  # Fiziksel konum
    rack_position = db.Column(db.String(50))  # Rack pozisyonu
    management_ip = db.Column(db.String(15))  # Management IP
    last_config_backup = db.Column(db.DateTime)
    last_monitoring_check = db.Column(db.DateTime)
    
    # Sunucu grupları ile ilişki
    group_memberships = db.relationship('ServerGroupMember', backref='server', cascade='all, delete-orphan')
    
    # Config backup'ları
    config_backups = db.relationship('ConfigBackup', backref='device', cascade='all, delete-orphan')
    
    # Interface bilgileri
    interfaces = db.relationship('NetworkInterface', backref='device', cascade='all, delete-orphan')
    
    # Monitoring verileri
    monitoring_data = db.relationship('DeviceMonitoring', backref='device', cascade='all, delete-orphan')

class ConfigBackup(db.Model):
    """Cihaz config backup'ları"""
    __tablename__ = 'config_backups'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    backup_name = db.Column(db.String(200), nullable=False)
    config_content = db.Column(db.Text, nullable=False)  # Config içeriği
    config_hash = db.Column(db.String(64), nullable=False)  # SHA256 hash
    backup_type = db.Column(db.String(20), default='manual')  # manual, scheduled, auto
    version = db.Column(db.String(50))  # Config versiyonu
    description = db.Column(db.Text)  # Backup açıklaması
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    file_size = db.Column(db.Integer)  # Byte cinsinden boyut
    
    # Backup'ı oluşturan kullanıcı
    user = db.relationship('User', backref='config_backups')

class NetworkInterface(db.Model):
    """Network interface bilgileri"""
    __tablename__ = 'network_interfaces'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    interface_name = db.Column(db.String(50), nullable=False)  # Gi0/1, Fa0/1, etc.
    interface_type = db.Column(db.String(20))  # Ethernet, FastEthernet, GigabitEthernet
    description = db.Column(db.String(200))
    ip_address = db.Column(db.String(15))
    subnet_mask = db.Column(db.String(15))
    status = db.Column(db.String(20), default='down')  # up, down, administratively down
    speed = db.Column(db.String(20))  # 100Mbps, 1Gbps, etc.
    duplex = db.Column(db.String(20))  # full, half, auto
    vlan = db.Column(db.Integer)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)

class DeviceMonitoring(db.Model):
    """Cihaz monitoring verileri"""
    __tablename__ = 'device_monitoring'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # CPU ve Memory
    cpu_usage = db.Column(db.Float)  # Yüzde
    memory_usage = db.Column(db.Float)  # Yüzde
    memory_total = db.Column(db.BigInteger)  # Total memory (bytes)
    memory_used = db.Column(db.BigInteger)  # Used memory (bytes)
    
    # Uptime
    uptime_seconds = db.Column(db.BigInteger)  # Uptime in seconds
    
    # Temperature (varsa)
    temperature = db.Column(db.Float)  # Celsius
    
    # Interface counters
    total_interfaces = db.Column(db.Integer)
    up_interfaces = db.Column(db.Integer)
    down_interfaces = db.Column(db.Integer)
    
    # Error counters
    interface_errors = db.Column(db.Integer)
    interface_drops = db.Column(db.Integer)

class ServerGroup(db.Model):
    """Sunucu grupları için model"""
    __tablename__ = 'server_groups'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    color = db.Column(db.String(20), default='primary')  # Bootstrap renk adı veya hex kodu
    icon = db.Column(db.String(50), default='fa-layer-group')  # FontAwesome ikon adı
    # Grup üyeleri
    members = db.relationship('ServerGroupMember', backref='group', cascade='all, delete-orphan')

class ServerGroupMember(db.Model):
    """Sunucu grup üyeleri için model"""
    __tablename__ = 'server_group_members'
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('server_groups.id'), nullable=False)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    added_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

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
    
    # Çıktı ve timeout ayarları
    wait_for_output = db.Column(db.Boolean, default=True)  # Çıktı beklesin mi?
    default_timeout = db.Column(db.Integer, default=60)  # Varsayılan timeout (saniye)
    is_long_running = db.Column(db.Boolean, default=False)  # Uzun süren script mi?
    
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
