"""
ÖZSOY PANEL - GÜNCELLENMİŞ & GÜVENLIKLI VERSIYON
- Tüm API'ler yeni endpoint'lerle güncellendi
- Render uyumlu
- DDoS korumalı
- Kullanıcı takip sistemi
"""

from datetime import datetime, timedelta
import os
import secrets
import string
import requests
import time
import json
import re
import hashlib
import ipaddress
from functools import wraps
from collections import defaultdict, deque

from flask import Flask, request, session, jsonify, render_template, redirect, url_for, flash, g
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

# ----------------------------------------------------------------------------
# FLASK APP & RENDER KONFIGÜRASYONU
# ----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'keneviz.sqlite')

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_urlsafe(64))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['PREFERRED_URL_SCHEME'] = 'https' if os.environ.get('FLASK_ENV') == 'production' else 'http'

# Render için proxy fix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

db = SQLAlchemy(app)

# Rate Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Sabit FREE_KEY
SABIT_FREE_KEY = "FREESORGUPANELI2025A"

# ----------------------------------------------------------------------------
# DDoS KORUMA & IP TAKIP SISTEMI
# ----------------------------------------------------------------------------
class DDOSProtection:
    def __init__(self):
        self.request_log = defaultdict(lambda: deque(maxlen=100))
        self.blocked_ips = set()
        self.suspicious_ips = set()
        
    def is_rate_limited(self, ip, endpoint, window=60, max_requests=30):
        """Rate limit kontrolü"""
        now = time.time()
        key = f"{ip}:{endpoint}"
        
        # Temizleme
        while self.request_log[key] and self.request_log[key][0] < now - window:
            self.request_log[key].popleft()
        
        # Kontrol
        if len(self.request_log[key]) >= max_requests:
            self.suspicious_ips.add(ip)
            return True
        
        self.request_log[key].append(now)
        return False
    
    def is_blocked(self, ip):
        """IP engellendi mi kontrolü"""
        return ip in self.blocked_ips
    
    def block_ip(self, ip, reason="DDoS şüphesi"):
        """IP engelle"""
        self.blocked_ips.add(ip)
        print(f"[DDoS] IP engellendi: {ip} - Sebep: {reason}")
    
    def is_suspicious(self, ip):
        """Şüpheli IP kontrolü"""
        return ip in self.suspicious_ips

ddos_protection = DDOSProtection()

# ----------------------------------------------------------------------------
# KULLANICI TAKIP SISTEMI
# ----------------------------------------------------------------------------
class UserTracker:
    def __init__(self):
        self.user_activity = defaultdict(dict)
        self.api_usage = defaultdict(lambda: defaultdict(int))
        self.suspicious_users = set()
        
    def track_login(self, ip, user_agent, key_id):
        """Giriş takibi"""
        self.user_activity[ip] = {
            'last_login': datetime.now(),
            'user_agent': user_agent,
            'key_id': key_id,
            'failed_attempts': 0,
            'api_calls_today': 0,
            'last_api_call': None
        }
    
    def track_api_call(self, ip, api_name, success=True):
        """API çağrısı takibi"""
        if ip in self.user_activity:
            self.user_activity[ip]['last_api_call'] = datetime.now()
            self.user_activity[ip]['api_calls_today'] += 1
            self.api_usage[ip][api_name] += 1
            
            # Şüpheli aktivite kontrolü
            if self.user_activity[ip]['api_calls_today'] > 100:  # Günde 100'den fazla çağrı
                self.suspicious_users.add(ip)
                print(f"[Takip] Şüpheli kullanıcı: {ip} - Günde {self.user_activity[ip]['api_calls_today']} API çağrısı")
    
    def track_failed_login(self, ip):
        """Başarısız giriş takibi"""
        if ip in self.user_activity:
            self.user_activity[ip]['failed_attempts'] += 1
            
            if self.user_activity[ip]['failed_attempts'] > 5:  # 5'ten fazla başarısız giriş
                ddos_protection.block_ip(ip, "Çok fazla başarısız giriş denemesi")
                return True
        return False
    
    def reset_daily_counts(self):
        """Günlük sayıları sıfırla"""
        for ip in self.user_activity:
            self.user_activity[ip]['api_calls_today'] = 0
    
    def get_user_stats(self, ip):
        """Kullanıcı istatistikleri"""
        return self.user_activity.get(ip, {})

user_tracker = UserTracker()

# Günlük sıfırlama için timer
def reset_daily_counts():
    while True:
        time.sleep(86400)  # 24 saat
        user_tracker.reset_daily_counts()

# Thread başlat
import threading
reset_thread = threading.Thread(target=reset_daily_counts, daemon=True)
reset_thread.start()

# ----------------------------------------------------------------------------
# MODELS
# ----------------------------------------------------------------------------
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    login_ip = db.Column(db.String(45), nullable=True)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    plan = db.Column(db.String(32), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    expires_at = db.Column(db.DateTime, nullable=True)
    active = db.Column(db.Boolean, default=True)
    notes = db.Column(db.Text, nullable=True)
    owner = db.Column(db.String(200), nullable=True)
    last_used = db.Column(db.DateTime, nullable=True)
    usage_count = db.Column(db.Integer, default=0)
    last_ip = db.Column(db.String(45), nullable=True)
    
    def is_expired(self):
        if not self.expires_at:
            return False
        return datetime.now() > self.expires_at

    def is_vip(self):
        return self.plan != 'free'

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.Text, nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)
    key_id = db.Column(db.Integer, nullable=True)
    endpoint = db.Column(db.String(200), nullable=True)

# ----------------------------------------------------------------------------
# YARDIMCI FONKSIYONLAR
# ----------------------------------------------------------------------------
def init_db():
    with app.app_context():
        db.create_all()

        # Admin oluştur
        if Admin.query.first() is None:
            admin = Admin(username='admin', password_hash=generate_password_hash('admin123'))
            db.session.add(admin)
            db.session.commit()
            print("[INFO] Admin: admin / admin123")

        # Free key oluştur
        if not Key.query.filter_by(key=SABIT_FREE_KEY).first():
            free_key = Key(
                key=SABIT_FREE_KEY,
                plan='free',
                created_at=datetime.now(),
                expires_at=None,
                active=True,
                notes='Sabit Free Key',
                owner='SYSTEM'
            )
            db.session.add(free_key)
            db.session.commit()
            print(f"[INFO] FREE Key: {SABIT_FREE_KEY}")

def generate_key_string(length=20):
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

PLAN_TO_DAYS = {
    '1hafta': 7,
    '1ay': 30,
    '3ay': 90,
    '1yil': 365,
    'free': None
}

def create_key(plan='1ay', notes=None, owner=None):
    while True:
        k = generate_key_string(20)
        if not Key.query.filter_by(key=k).first():
            break

    expires = None
    days = PLAN_TO_DAYS.get(plan)
    if days:
        expires = datetime.now() + timedelta(days=days)

    key = Key(
        key=k,
        plan=plan,
        expires_at=expires,
        notes=notes,
        owner=owner,
        active=True
    )
    db.session.add(key)
    db.session.commit()

    print(f"[KEY] {k} ({plan}) oluşturuldu")
    return key

def verify_key_string(kstr):
    if not kstr or not kstr.strip():
        return None

    kstr = kstr.strip()

    # Sabit free key
    if kstr == SABIT_FREE_KEY:
        key = Key.query.filter_by(key=SABIT_FREE_KEY).first()
        if not key:
            key = Key(
                key=SABIT_FREE_KEY,
                plan='free',
                created_at=datetime.now(),
                expires_at=None,
                active=True,
                notes='Sabit Free Key',
                owner='SYSTEM'
            )
            db.session.add(key)
            db.session.commit()
        return key

    # Normal key
    key = Key.query.filter_by(key=kstr).first()

    if not key:
        return None

    if not key.active:
        return None

    if key.is_expired():
        key.active = False
        db.session.commit()
        return None

    return key

def log_audit(action, details=None, key_id=None):
    """Audit log kaydı"""
    try:
        ip = get_remote_address()
        user_agent = request.headers.get('User-Agent', '')
        endpoint = request.endpoint
        
        log = AuditLog(
            ip_address=ip,
            user_agent=user_agent,
            action=action,
            details=details,
            key_id=key_id,
            endpoint=endpoint
        )
        db.session.add(log)
        db.session.commit()
    except:
        pass

# ----------------------------------------------------------------------------
# GÜVENLIK MIDDLEWARE'LERI
# ----------------------------------------------------------------------------
def get_client_ip():
    """Client IP adresini güvenli şekilde al"""
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        ip = request.remote_addr
    
    # IP doğrulama
    try:
        ipaddress.ip_address(ip)
        return ip
    except:
        return '0.0.0.0'

def security_middleware(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = get_client_ip()
        
        # DDoS kontrolü
        if ddos_protection.is_blocked(client_ip):
            return jsonify({'error': 'Erişim engellendi'}), 403
        
        # Rate limit kontrolü
        endpoint = request.endpoint or 'unknown'
        if ddos_protection.is_rate_limited(client_ip, endpoint):
            ddos_protection.block_ip(client_ip, "Rate limit aşıldı")
            return jsonify({'error': 'Çok fazla istek'}), 429
        
        # User-Agent kontrolü
        user_agent = request.headers.get('User-Agent', '')
        if not user_agent or len(user_agent) < 10:
            ddos_protection.suspicious_ips.add(client_ip)
        
        # Bot kontrolü
        bot_patterns = [
            'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget',
            'python-requests', 'java', 'php', 'go-http', 'ruby'
        ]
        if any(pattern in user_agent.lower() for pattern in bot_patterns):
            if not request.path.startswith('/api/'):  # API endpointlerine izin ver
                ddos_protection.suspicious_ips.add(client_ip)
        
        return f(*args, **kwargs)
    return decorated_function

def validate_input(data, allowed_patterns=None):
    """Giriş doğrulama"""
    if not data:
        return False
    
    # SQL Injection pattern'leri
    sql_patterns = [
        r'(\%27)|(\')|(\-\-)|(\%23)|(#)',
        r'((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))',
        r'\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))',
        r'((\%27)|(\'))union'
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, data, re.IGNORECASE):
            return False
    
    # XSS pattern'leri
    xss_patterns = [
        r'<script.*?>.*?</script>',
        r'javascript:',
        r'onclick=',
        r'onload=',
        r'onerror='
    ]
    
    for pattern in xss_patterns:
        if re.search(pattern, data, re.IGNORECASE):
            return False
    
    # Özel pattern kontrolü
    if allowed_patterns:
        for pattern in allowed_patterns:
            if re.match(pattern, data):
                return True
        return False
    
    return True

# ----------------------------------------------------------------------------
# DECORATOR'LAR
# ----------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = get_client_ip()
        
        if 'key' not in session:
            log_audit("Oturum yok", key_id=None)
            return redirect(url_for('login'))

        key_str = session.get('key')
        key = verify_key_string(key_str)
        
        if not key:
            session.clear()
            user_tracker.track_failed_login(client_ip)
            log_audit("Geçersiz key", key_str, None)
            flash('Key geçersiz veya süresi dolmuş')
            return redirect(url_for('login'))

        # Key kullanımını güncelle
        key.last_used = datetime.now()
        key.usage_count += 1
        key.last_ip = client_ip
        db.session.commit()
        
        log_audit("Oturum erişimi", f"Key: {key.key[:8]}...", key.id)
        
        return f(*args, **kwargs)
    return decorated_function

# ----------------------------------------------------------------------------
# GÜNCELLENMİŞ API LISTESI - TÜM API'LER YENİLENDİ
# ----------------------------------------------------------------------------
APIS = {
    # ============== TC VE GSM API'LERİ (Zyrdaware) ==============
    'adsoyad': {
        'name': 'Ad Soyad TC Sorgu',
        'plan': 'free',
        'endpoint': 'https://zyrdaware.xyz/api/adsoyad?auth=t.me/zyrdaware&ad={ad}&soyad={soyad}',
        'params': ['ad', 'soyad']
    },
    
    'gsmtc': {
        'name': 'GSM → TC Sorgu',
        'plan': 'free',
        'endpoint': 'https://zyrdaware.xyz/api/gsmtc?auth=t.me/zyrdaware&gsm={gsm}',
        'params': ['gsm']
    },
    
    'tcgsm': {
        'name': 'TC → GSM Sorgu',
        'plan': 'vip',
        'endpoint': 'https://zyrdaware.xyz/api/tcgsm?auth=t.me/zyrdaware&tc={tc}',
        'params': ['tc']
    },
    
    # ============== PLAKA API'LERİ (PlakaF3) ==============
    'plaka': {
        'name': 'TC → Plaka Sorgu',
        'plan': 'vip',
        'endpoint': 'https://plakaf3.onrender.com/f3/api/plaka?tc={tc}',
        'params': ['tc']
    },
    
    'adsoyadplaka': {
        'name': 'Ad Soyad Plaka Sorgu',
        'plan': 'vip',
        'endpoint': 'https://plakaf3.onrender.com/f3/api/adsoyadplaka?ad={ad}&soyad={soyad}',
        'params': ['ad', 'soyad']
    },
    
    'adplaka': {
        'name': 'Sadece Ad Plaka Sorgu',
        'plan': 'vip',
        'endpoint': 'https://plakaf3.onrender.com/f3/api/adsoyadplaka?ad={ad}',
        'params': ['ad']
    },
    
    'soyadplaka': {
        'name': 'Sadece Soyad Plaka Sorgu',
        'plan': 'vip',
        'endpoint': 'https://plakaf3.onrender.com/f3/api/adsoyadplaka?soyad={soyad}',
        'params': ['soyad']
    },
    
    # ============== PAPARA API'LERİ ==============
    'papara': {
        'name': 'Papara Numarası Sorgu',
        'plan': 'vip',
        'endpoint': 'https://paparadata.onrender.com/f3system/api/papara?paparano={paparano}',
        'params': ['paparano']
    },
    
    'adsoyadpapara': {
        'name': 'Ad Soyad Papara Sorgu',
        'plan': 'vip',
        'endpoint': 'https://paparadata.onrender.com/f3system/api/papara?ad={ad}&soyad={soyad}',
        'params': ['ad', 'soyad']
    },
    
    'adpapara': {
        'name': 'Sadece Ad Papara Sorgu',
        'plan': 'vip',
        'endpoint': 'https://paparadata.onrender.com/f3system/api/papara?ad={ad}',
        'params': ['ad']
    },
    
    'papara_alternatif': {
        'name': 'Papara Sorgu (Alternatif)',
        'plan': 'vip',
        'endpoint': 'https://paparadataf3.onrender.com/f3system/api/papara?paparano={paparano}',
        'params': ['paparano']
    },
    
    # ============== ECZANE API'LERİ ==============
    'adeczane': {
        'name': 'Ad Eczane Sorgu',
        'plan': 'vip',
        'endpoint': 'https://eczanedataf3.onrender.com/f3system/api/eczane?ad={ad}',
        'params': ['ad']
    },
    
    'ileczane': {
        'name': 'İl Eczane Sorgu',
        'plan': 'vip',
        'endpoint': 'https://eczanedataf3.onrender.com/f3system/api/eczane?il={il}',
        'params': ['il']
    },
    
    # ============== SERİ NO API'LERİ ==============
    'tcserino': {
        'name': 'TC Seri No Sorgu',
        'plan': 'vip',
        'endpoint': 'https://serinodataf3.onrender.com/serino?tc={tc}',
        'params': ['tc']
    },
    
    'adsoyadserino': {
        'name': 'Ad Soyad Seri No Sorgu',
        'plan': 'vip',
        'endpoint': 'https://serinodataf3.onrender.com/serino?ad={ad}&soyad={soyad}',
        'params': ['ad', 'soyad']
    },
    
    'adserino': {
        'name': 'Sadece Ad Seri No Sorgu',
        'plan': 'vip',
        'endpoint': 'https://serinodataf3.onrender.com/serino?ad={ad}',
        'params': ['ad']
    },
    
    'soyadserino': {
        'name': 'Sadece Soyad Seri No Sorgu',
        'plan': 'vip',
        'endpoint': 'https://serinodataf3.onrender.com/serino?soyad={soyad}',
        'params': ['soyad']
    },
    
    'ililceserino': {
        'name': 'İl İlçe Seri No Sorgu',
        'plan': 'vip',
        'endpoint': 'https://serinodataf3.onrender.com/serino?il={il}&ilce={ilce}',
        'params': ['il', 'ilce']
    },
    
    'serino_direct': {
        'name': 'Seri No Doğrudan Sorgu',
        'plan': 'vip',
        'endpoint': 'https://serinodataf3.onrender.com/serino?seri_no={seri_no}',
        'params': ['seri_no']
    },
    
    'adilserino': {
        'name': 'Ad İl Seri No Sorgu',
        'plan': 'vip',
        'endpoint': 'https://serinodataf3.onrender.com/serino?ad={ad}&il={il}&limit={limit}',
        'params': ['ad', 'il', 'limit']
    },
    
    # ============== VERGİ API'LERİ ==============
    'advergi': {
        'name': 'Ad Vergi Sorgu',
        'plan': 'vip',
        'endpoint': 'https://vergidata-hv43.onrender.com/f3system/api/vergi?isim={isim}',
        'params': ['isim']
    },
    
    'ilcevergidairesi': {
        'name': 'İlçe Vergi Dairesi Sorgu',
        'plan': 'vip',
        'endpoint': 'https://vergidata-hv43.onrender.com/f3system/api/vergi?ilce={ilce}&vergi_dairesi={vergi_dairesi}',
        'params': ['ilce', 'vergi_dairesi']
    },
    
    'vergino': {
        'name': 'Vergi No Sorgulama',
        'plan': 'vip',
        'endpoint': 'https://vergidata-hv43.onrender.com/f3system/api/vergi?vergi_no={vergi_no}',
        'params': ['vergi_no']
    },
    
    'vergilimit': {
        'name': 'Vergi Limitli Sorgu',
        'plan': 'vip',
        'endpoint': 'https://vergidata-hv43.onrender.com/f3system/api/vergi?limit={limit}',
        'params': ['limit']
    },
    
    # ============== PHISHING API'LERİ ==============
    'phishing_create': {
        'name': 'Phishing Link Oluşturma',
        'plan': 'vip',
        'endpoint': 'https://phishing-n3gi.onrender.com/create_link?token={token}&id={id}&template={template}',
        'params': ['token', 'id', 'template']
    },
    
    'phishing_instagram': {
        'name': 'Instagram Phishing',
        'plan': 'vip',
        'endpoint': 'https://phishing-n3gi.onrender.com/instagram?token={token}&id={id}',
        'params': ['token', 'id']
    },
    
    'phishing_facebook': {
        'name': 'Facebook Phishing',
        'plan': 'vip',
        'endpoint': 'https://phishing-n3gi.onrender.com/facebook?token={token}&id={id}',
        'params': ['token', 'id']
    },
    
    'phishing_netflix': {
        'name': 'Netflix Phishing',
        'plan': 'vip',
        'endpoint': 'https://phishing-n3gi.onrender.com/netflix?token={token}&id={id}',
        'params': ['token', 'id']
    },
    
    'phishing_tiktok': {
        'name': 'TikTok Phishing',
        'plan': 'vip',
        'endpoint': 'https://phishing-n3gi.onrender.com/tiktok?token={token}&id={id}',
        'params': ['token', 'id']
    },
    
    'phishing_twitter': {
        'name': 'Twitter Phishing',
        'plan': 'vip',
        'endpoint': 'https://phishing-n3gi.onrender.com/twitter?token={token}&id={id}',
        'params': ['token', 'id']
    },
    
    'phishing_google': {
        'name': 'Google Phishing',
        'plan': 'vip',
        'endpoint': 'https://phishing-n3gi.onrender.com/google?token={token}&id={id}',
        'params': ['token', 'id']
    },
    
    'phishing_microsoft': {
        'name': 'Microsoft Phishing',
        'plan': 'vip',
        'endpoint': 'https://phishing-n3gi.onrender.com/microsoft?token={token}&id={id}',
        'params': ['token', 'id']
    },
    
    'phishing_spotify': {
        'name': 'Spotify Phishing',
        'plan': 'vip',
        'endpoint': 'https://phishing-n3gi.onrender.com/spotify?token={token}&id={id}',
        'params': ['token', 'id']
    },
    
    'phishing_steam': {
        'name': 'Steam Phishing',
        'plan': 'vip',
        'endpoint': 'https://phishing-n3gi.onrender.com/steam?token={token}&id={id}',
        'params': ['token', 'id']
    },
    
    'phishing_discord': {
        'name': 'Discord Phishing',
        'plan': 'vip',
        'endpoint': 'https://phishing-n3gi.onrender.com/discord?token={token}&id={id}',
        'params': ['token', 'id']
    },
    
    'phishing_paypal': {
        'name': 'PayPal Phishing',
        'plan': 'vip',
        'endpoint': 'https://phishing-n3gi.onrender.com/paypal?token={token}&id={id}',
        'params': ['token', 'id']
    },
    
    'phishing_amazon': {
        'name': 'Amazon Phishing',
        'plan': 'vip',
        'endpoint': 'https://phishing-n3gi.onrender.com/amazon?token={token}&id={id}',
        'params': ['token', 'id']
    },
    
    'phishing_apple': {
        'name': 'Apple Phishing',
        'plan': 'vip',
        'endpoint': 'https://phishing-n3gi.onrender.com/apple?token={token}&id={id}',
        'params': ['token', 'id']
    },
    
    'phishing_epicgames': {
        'name': 'Epic Games Phishing',
        'plan': 'vip',
        'endpoint': 'https://phishing-n3gi.onrender.com/epicgames?token={token}&id={id}',
        'params': ['token', 'id']
    },
    
    'phishing_whatsapp': {
        'name': 'WhatsApp Phishing',
        'plan': 'vip',
        'endpoint': 'https://phishing-n3gi.onrender.com/whatsapp?token={token}&id={id}',
        'params': ['token', 'id']
    },
    
    # ============== PANEL API'LERİ (Kapsamlı) ==============
    'nufus': {
        'name': 'Nüfus Sorgulama',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/nufus/sorgu?tc={tc}',
        'params': ['tc']
    },
    
    'asi_kayitlari': {
        'name': 'Aşı Kayıtları',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/saglik/asi-kayitlari?tc={tc}',
        'params': ['tc']
    },
    
    'rontgen_listesi': {
        'name': 'Röntgen Listesi',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/saglik/rontgen-listesi?tc={tc}',
        'params': ['tc']
    },
    
    'recete_gecmisi': {
        'name': 'Reçete Geçmişi',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/eczane/recete-gecmisi?tc={tc}',
        'params': ['tc']
    },
    
    'adli_sicil': {
        'name': 'Adli Sicil Kaydı',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/adli-sicil/kayit?tc={tc}',
        'params': ['tc']
    },
    
    'pasaport': {
        'name': 'Pasaport Sorgu',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/pasaport/sorgu?tc={tc}',
        'params': ['tc']
    },
    
    'ehliyet': {
        'name': 'Ehliyet Sorgu',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/ehliyet/sorgu?tc={tc}',
        'params': ['tc']
    },
    
    'arac_sahibi': {
        'name': 'Araç Sahibi Sorgu',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/trafik/arac-sahibi?tc={tc}',
        'params': ['tc']
    },
    
    'sgk_ise_giris': {
        'name': 'SGK İşe Giriş',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/sgk/ise-giris?tc={tc}',
        'params': ['tc']
    },
    
    'ogrenci_durum': {
        'name': 'Öğrenci Durumu',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/yok/ogrenci-durum?tc={tc}',
        'params': ['tc']
    },
    
    'kronik_hastalik': {
        'name': 'Kronik Hastalık',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/saglik/kronik-hastalik?tc={tc}',
        'params': ['tc']
    },
    
    'vergi_borc': {
        'name': 'Vergi Borç Sorgu',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/vergi/borc-sorgu?tc={tc}',
        'params': ['tc']
    },
    
    'tapu_gayrimenkul': {
        'name': 'Tapu Gayrimenkul',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/tapu/gayrimenkul?tc={tc}',
        'params': ['tc']
    },
    
    'askerlik_durum': {
        'name': 'Askerlik Durumu',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/askerlik/durum?tc={tc}',
        'params': ['tc']
    },
    
    'su_fatura': {
        'name': 'Su Faturası',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/ibb/su-fatura?tc={tc}',
        'params': ['tc']
    },
    
    'elektrik_fatura': {
        'name': 'Elektrik Faturası',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/elektrik/fatura?tc={tc}',
        'params': ['tc']
    },
    
    'otel_rezervasyon': {
        'name': 'Otel Rezervasyon',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/turizm/otel-rezervasyon?tc={tc}',
        'params': ['tc']
    },
    
    'istanbulkart_bakiye': {
        'name': 'İstanbulkart Bakiye',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/ulasim/istanbulkart-bakiye?tc={tc}',
        'params': ['tc']
    },
    
    'spor_federasyon': {
        'name': 'Spor Federasyon Kaydı',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/spor/federasyon/kayit?tc={tc}',
        'params': ['tc']
    },
    
    'kutuphane_uye': {
        'name': 'Kütüphane Üye Durumu',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/kutuphane/uye-durum?tc={tc}',
        'params': ['tc']
    },
    
    'hasta_yatis': {
        'name': 'Hasta Yatış Geçmişi',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/saglik/hasta-yatis-gecmisi?tc={tc}',
        'params': ['tc']
    },
    
    'banka_musteri': {
        'name': 'Banka Müşteri Bilgisi',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/dijital/banka-musteri?tc={tc}',
        'params': ['tc']
    },
    
    'kredi_risk': {
        'name': 'Kredi Risk Raporu',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/kredi/risk-raporu?tc={tc}',
        'params': ['tc']
    },
    
    'meb_mezuniyet': {
        'name': 'MEB Mezuniyet',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/meb/mezuniyet?tc={tc}',
        'params': ['tc']
    },
    
    'ticaret_sikayet': {
        'name': 'Ticaret Şikayet Kaydı',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/ticaret/sikayet-kaydi?tc={tc}',
        'params': ['tc']
    },
    
    'cevre_ceza': {
        'name': 'Çevre Ceza',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/cevre/sehirlerarasi-ceza?tc={tc}',
        'params': ['tc']
    },
    
    'noter_islem': {
        'name': 'Noter İşlem',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/noter/gereceklesen-islem?tc={tc}',
        'params': ['tc']
    },
    
    'avci_lisans': {
        'name': 'Avcı Lisans',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/ormancilik/avci-lisans?tc={tc}',
        'params': ['tc']
    },
    
    'ucak_bilet': {
        'name': 'Uçak Bileti',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/udhb/ucak-bilet?tc={tc}',
        'params': ['tc']
    },
    
    'seyahat_hareket': {
        'name': 'Seyahat Hareket',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/mzk/seyahat-hareket?tc={tc}',
        'params': ['tc']
    },
}

# ----------------------------------------------------------------------------
# ROUTE'LAR - GÜVENLIKLI VERSIYON
# ----------------------------------------------------------------------------
@app.before_request
def before_request():
    g.client_ip = get_client_ip()
    
    # DDoS engelleme kontrolü
    if ddos_protection.is_blocked(g.client_ip):
        return jsonify({'error': 'Erişim engellendi'}), 403

@app.route('/')
@security_middleware
def index():
    return redirect(url_for('robot_dogrulama'))

@app.route('/robot_dogrulama')
@security_middleware
@limiter.limit("10 per minute")
def robot_dogrulama():
    next_page = request.args.get('next', '/login')
    return render_template('robot_dogrulama.html', next_page=next_page)

@app.route('/keneviz_challenge', methods=['POST'])
@security_middleware
@limiter.limit("5 per minute")
def keneviz_challenge():
    nonce = secrets.token_urlsafe(16)
    session['keneviz_challenge'] = {
        'nonce': nonce,
        'ts': int(time.time()),
        'tries': 0,
        'ip': g.client_ip
    }
    session.modified = True
    log_audit("Challenge oluşturuldu", nonce)
    return jsonify({'challenge_id': nonce, 'ts': session['keneviz_challenge']['ts']})

@app.route('/keneviz_verify', methods=['POST'])
@security_middleware
@limiter.limit("5 per minute")
def keneviz_verify():
    try:
        data = request.get_json() or {}
        saved = session.get('keneviz_challenge')
        
        if not saved:
            log_audit("Challenge bulunamadı")
            return jsonify({'success': False, 'error': 'no_challenge'}), 400
        
        # IP kontrolü
        if saved.get('ip') != g.client_ip:
            log_audit("IP uyuşmazlığı", f"{saved.get('ip')} != {g.client_ip}")
            return jsonify({'success': False, 'error': 'ip_mismatch'}), 400
        
        incoming_nonce = data.get('challenge_id')
        if not incoming_nonce or incoming_nonce != saved.get('nonce'):
            log_audit("Challenge uyuşmazlığı")
            return jsonify({'success': False, 'error': 'challenge_mismatch'}), 400
        
        # Zaman kontrolü (5 dakika)
        if time.time() - saved.get('ts', 0) > 300:
            log_audit("Challenge timeout")
            return jsonify({'success': False, 'error': 'timeout'}), 400
        
        session['keneviz_verified'] = True
        session.pop('keneviz_challenge', None)
        session.modified = True
        
        log_audit("Challenge doğrulandı")
        
        return jsonify({
            'success': True,
            'verification_token': 'verified',
            'redirect': data.get('next', '/login')
        })
    except Exception as e:
        log_audit("Challenge hatası", str(e))
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/login', methods=['GET', 'POST'])
@security_middleware
@limiter.limit("10 per minute", methods=['POST'])
def login():
    if not session.get('keneviz_verified'):
        return redirect(url_for('robot_dogrulama') + '?next=/login')
    
    if request.method == 'GET':
        return render_template('login.html')
    
    key_str = request.form.get('key', '').strip()
    
    # Giriş doğrulama
    if not validate_input(key_str, allowed_patterns=[r'^[A-Z0-9]{20}$']):
        user_tracker.track_failed_login(g.client_ip)
        log_audit("Geçersiz key formatı", key_str)
        flash('Geçersiz key formatı')
        return redirect(url_for('login'))
    
    key = verify_key_string(key_str)
    
    if not key:
        user_tracker.track_failed_login(g.client_ip)
        log_audit("Geçersiz key", key_str)
        flash('Geçersiz veya süresi dolmuş key')
        return redirect(url_for('login'))
    
    # User tracker güncelleme
    user_agent = request.headers.get('User-Agent', '')
    user_tracker.track_login(g.client_ip, user_agent, key.id)
    
    session['key'] = key.key
    session['plan'] = key.plan
    session['key_id'] = key.id
    session['logged_in'] = True
    session['username'] = f"user{key.id}"
    session['is_vip'] = key.plan != 'free'
    session['login_ip'] = g.client_ip
    
    session.pop('keneviz_verified', None)
    session.modified = True
    
    log_audit("Başarılı giriş", f"Key: {key.key[:8]}... Plan: {key.plan}", key.id)
    
    return redirect(url_for('panel'))

@app.route('/logout')
@security_middleware
def logout():
    key_id = session.get('key_id')
    log_audit("Çıkış yapıldı", key_id=key_id)
    session.clear()
    return redirect(url_for('login'))

@app.route('/panel')
@security_middleware
@login_required
@limiter.limit("30 per minute")
def panel():
    key_str = session.get('key')
    key = verify_key_string(key_str)
    
    if not key:
        session.clear()
        flash('Key geçersiz veya süresi dolmuş')
        return redirect(url_for('login'))
    
    # Kullanıcı istatistikleri
    user_stats = user_tracker.get_user_stats(g.client_ip)
    
    user_plan = key.plan
    plan_name = "VIP" if user_plan != 'free' else "FREE"
    username = session.get('username', f"user{key.id}")
    is_vip = user_plan != 'free'
    
    remaining = "Sınırsız"
    remaining_days = None
    if key.expires_at:
        remaining_days = (key.expires_at - datetime.now()).days
        if remaining_days > 0:
            remaining = f"{remaining_days} gün"
        else:
            key.active = False
            db.session.commit()
            session.clear()
            log_audit("Key süresi doldu", key_id=key.id)
            flash('Key süreniz dolmuş')
            return redirect(url_for('login'))
    
    total_apis = len(APIS)
    free_apis = len([a for a in APIS.values() if a['plan'] == 'free'])
    vip_apis = len([a for a in APIS.values() if a['plan'] == 'vip'])
    
    user_apis = total_apis if is_vip else free_apis
    
    # Kullanıcı takip bilgileri
    today_calls = user_stats.get('api_calls_today', 0)
    last_login = user_stats.get('last_login', datetime.now())
    last_api = user_stats.get('last_api_call', 'Henüz yok')
    
    return render_template('panel.html',
                         key=key,
                         username=username,
                         plan_name=plan_name,
                         remaining=remaining,
                         total_apis=total_apis,
                         free_apis=free_apis,
                         vip_apis=vip_apis,
                         user_apis=user_apis,
                         free_key=SABIT_FREE_KEY,
                         is_vip=is_vip,
                         user_plan=user_plan,
                         today_calls=today_calls,
                         last_login=last_login,
                         last_api=last_api,
                         user_ip=g.client_ip)

@app.route('/sorgu.html')
@security_middleware
@login_required
@limiter.limit("20 per minute")
def sorgu_page():
    api_name = request.args.get('api', '').lower()
    
    if not api_name:
        return redirect(url_for('panel'))
    
    if api_name not in APIS:
        return f"<h1>Geçersiz API: {api_name}</h1>", 404
    
    key_str = session.get('key')
    key = verify_key_string(key_str)
    
    if not key:
        session.clear()
        flash('Key geçersiz veya süresi dolmuş')
        return redirect(url_for('login'))
    
    api_plan = APIS[api_name]['plan']
    user_plan = key.plan
    is_vip = user_plan != 'free'
    
    if api_plan == 'vip' and not is_vip:
        log_audit("VIP erişim reddedildi", f"API: {api_name}, Key: {key.key[:8]}...", key.id)
        return render_template('vip_required.html', 
                             api_name=APIS[api_name]['name'],
                             user_plan=user_plan)
    
    log_audit("API sayfası erişimi", f"API: {api_name}", key.id)
    
    return render_template('sorgu.html',
                         api_id=api_name,
                         api_info=APIS[api_name])

@app.route('/abonelik.html')
@security_middleware
def abonelik_page():
    return render_template('abonelik.html')

# ----------------------------------------------------------------------------
# API ENDPOINTS - GÜVENLİKLI ve GÜNCELLENMİŞ
# ----------------------------------------------------------------------------
@app.route('/api/user')
@security_middleware
def api_user():
    if 'key' not in session:
        return jsonify({'logged_in': False, 'role': 'guest'})
    
    key_str = session.get('key')
    key = verify_key_string(key_str)
    
    if not key:
        session.clear()
        return jsonify({'logged_in': False, 'role': 'guest'})
    
    role = 'vip' if key.plan != 'free' else 'free'
    
    return jsonify({
        'logged_in': True,
        'role': role,
        'plan': key.plan,
        'is_vip': key.plan != 'free',
        'username': session.get('username', f"user{key.id}"),
        'key': key.key[:8] + '...',
        'plan_name': "VIP" if key.plan != 'free' else "FREE"
    })

@app.route('/api/list')
@security_middleware
@login_required
@limiter.limit("10 per minute")
def api_list():
    key_str = session.get('key')
    key = verify_key_string(key_str)
    
    total = len(APIS)
    free = len([a for a in APIS.values() if a['plan'] == 'free'])
    vip = len([a for a in APIS.values() if a['plan'] == 'vip'])
    
    log_audit("API listesi alındı", key_id=key.id)
    
    return jsonify({
        'success': True,
        'total_apis': total,
        'free_apis': free,
        'vip_apis': vip
    })

@app.route('/api/sorgu', methods=['POST'])
@security_middleware
@login_required
@limiter.limit("10 per minute")
def api_sorgu():
    data = request.get_json() or {}
    api_id = data.get('api', '').lower()
    
    if not api_id:
        return jsonify({'success': False, 'error': 'API adı belirtilmemiş'}), 400
    
    if api_id not in APIS:
        return jsonify({'success': False, 'error': 'Geçersiz API'}), 404
    
    key_str = session.get('key')
    key = verify_key_string(key_str)
    
    if not key:
        session.clear()
        return jsonify({'success': False, 'error': 'Key geçersiz'}), 401
    
    api_plan = APIS[api_id]['plan']
    user_plan = key.plan
    is_vip = user_plan != 'free'
    
    if api_plan == 'vip' and not is_vip:
        log_audit("VIP API erişim reddedildi", f"API: {api_id}", key.id)
        return jsonify({
            'success': False,
            'error': f'Bu API için VIP üyelik gereklidir. Mevcut planınız: {user_plan}',
            'redirect': '/abonelik.html',
            'api_name': APIS[api_id]['name'],
            'user_plan': user_plan,
            'required_plan': 'vip'
        }), 403
    
    # Parametre doğrulama
    api_params = APIS[api_id]['params']
    for param in api_params:
        param_value = data.get(param, '')
        if not param_value:
            return jsonify({'success': False, 'error': f'{param} parametresi gereklidir'}), 400
        
        # TC doğrulama
        if param == 'tc' and not validate_input(str(param_value), allowed_patterns=[r'^\d{11}$']):
            return jsonify({'success': False, 'error': 'Geçersiz TC numarası'}), 400
        
        # GSM doğrulama
        if param == 'gsm' and not validate_input(str(param_value), allowed_patterns=[r'^\d{10}$']):
            return jsonify({'success': False, 'error': 'Geçersiz GSM numarası'}), 400
        
        # Papara no doğrulama
        if param == 'paparano' and not validate_input(str(param_value), allowed_patterns=[r'^\d+$']):
            return jsonify({'success': False, 'error': 'Geçersiz Papara numarası'}), 400
    
    api_endpoint = APIS[api_id]['endpoint']
    
    filled_endpoint = api_endpoint
    for param in api_params:
        param_value = data.get(param, '')
        filled_endpoint = filled_endpoint.replace(f'{{{param}}}', str(param_value))
    
    # User tracker güncelleme
    user_tracker.track_api_call(g.client_ip, api_id)
    
    try:
        # Headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Referer': 'https://panel.ozsoy.app/',
            'X-Forwarded-For': g.client_ip,
            'X-Requested-With': 'XMLHttpRequest'
        }
        
        # GZIP decode olmadan istek yap
        response = requests.get(filled_endpoint, headers=headers, timeout=30)
        
        log_audit("API çağrısı", f"API: {api_id}, Status: {response.status_code}", key.id)
        
        if response.status_code == 200:
            # Content-Type kontrolü
            content_type = response.headers.get('Content-Type', '').lower()
            
            # Eğer JSON ise
            if 'application/json' in content_type or 'json' in content_type:
                try:
                    result_data = response.json()
                    return jsonify({'success': True, 'data': result_data})
                except:
                    pass
            
            # Eğer HTML ise
            if 'text/html' in content_type or 'html' in content_type:
                try:
                    # HTML'i parse etmeyi dene
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.content, 'html.parser')
                    # Script ve style etiketlerini temizle
                    for script in soup(["script", "style"]):
                        script.decompose()
                    text = soup.get_text()
                    lines = (line.strip() for line in text.splitlines())
                    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
                    text = '\n'.join(chunk for chunk in chunks if chunk)
                    return jsonify({'success': True, 'data': text[:5000]})
                except:
                    pass
            
            # Eğer plain text ise
            if 'text/plain' in content_type or 'text/' in content_type:
                try:
                    # Farklı encoding'ler dene
                    encodings = ['utf-8', 'iso-8859-9', 'windows-1254', 'ascii']
                    text = None
                    for encoding in encodings:
                        try:
                            text = response.content.decode(encoding, errors='replace')
                            break
                        except:
                            continue
                    
                    if text:
                        # Türkçe karakter düzeltme
                        replacements = {
                            'Ã§': 'ç', 'Ã‡': 'Ç',
                            'ÄŸ': 'ğ', 'Äž': 'Ğ',
                            'Ã¶': 'ö', 'Ã–': 'Ö',
                            'ÅŸ': 'ş', 'Åž': 'Ş',
                            'Ã¼': 'ü', 'Ãœ': 'Ü',
                            'Ä±': 'ı', 'Ä°': 'İ',
                            'â€': '-', 'â€™': "'",
                            'â€œ': '"', 'â€': '"',
                            'â€˜': "'", 'â€¦': '...'
                        }
                        
                        for wrong, correct in replacements.items():
                            text = text.replace(wrong, correct)
                        
                        return jsonify({'success': True, 'data': text[:5000]})
                except:
                    pass
            
            # Hiçbiri çalışmazsa binary olarak göster
            try:
                # Hex formatına çevir
                hex_data = response.content.hex()
                # İlk 1000 karakter göster
                return jsonify({
                    'success': True, 
                    'data': f"Binary veri alındı (hex, {len(response.content)} bytes). İlk 1000 karakter: {hex_data[:1000]}...",
                    'raw_hex': hex_data,
                    'size_bytes': len(response.content),
                    'content_type': content_type
                })
            except:
                return jsonify({
                    'success': True, 
                    'data': f"Raw veri alındı ({len(response.content)} bytes)",
                    'size': len(response.content)
                })
        else:
            return jsonify({
                'success': False,
                'error': f'API hatası: {response.status_code}',
                'response': response.text[:500] if response.text else 'No response text'
            }), response.status_code
    except requests.Timeout:
        log_audit("API timeout", f"API: {api_id}", key.id)
        return jsonify({'success': False, 'error': 'API yanıt vermedi (timeout). Lütfen daha sonra tekrar deneyin.'}), 504
    except requests.ConnectionError:
        log_audit("API bağlantı hatası", f"API: {api_id}", key.id)
        return jsonify({'success': False, 'error': 'API sunucusuna bağlanılamadı.'}), 503
    except requests.RequestException as e:
        log_audit("API hatası", f"API: {api_id}, Hata: {str(e)}", key.id)
        return jsonify({'success': False, 'error': f'İstek hatası: {str(e)}'}), 500

# ----------------------------------------------------------------------------
# KEY OLUŞTURMA API - GÜVENLIKLI
# ----------------------------------------------------------------------------
@app.route('/adminapi/createkey')
@security_middleware
@limiter.limit("5 per minute")
def adminapi_createkey():
    # Çoklu auth yöntemi
    auth = (request.args.get('auth') or 
            request.headers.get('X-Auth-Key') or 
            request.headers.get('Authorization', '').replace('Bearer ', ''))
    
    if auth != 'admin123':
        log_audit("Yetkisiz admin erişimi", f"IP: {g.client_ip}")
        return jsonify({'success': False, 'error': 'Yetkisiz erişim'}), 401
    
    plan = request.args.get('plan', '1ay')
    owner = request.args.get('owner', 'API User')
    notes = request.args.get('notes', f'API ile oluşturuldu - {datetime.now().strftime("%Y-%m-%d")}')
    
    if plan not in PLAN_TO_DAYS:
        return jsonify({'success': False, 'error': 'Geçersiz plan'}), 400
    
    try:
        key = create_key(plan=plan, notes=notes, owner=owner)
        
        expires_info = "Süresiz" if not key.expires_at else key.expires_at.strftime("%d/%m/%Y %H:%M")
        
        log_audit("Key oluşturuldu", f"Plan: {plan}, Owner: {owner}", key.id)
        
        return jsonify({
            'success': True,
            'key': key.key,
            'plan': key.plan,
            'created_at': key.created_at.strftime("%d/%m/%Y %H:%M"),
            'expires_at': expires_info,
            'owner': key.owner,
            'notes': key.notes
        })
    except Exception as e:
        log_audit("Key oluşturma hatası", str(e))
        return jsonify({'success': False, 'error': str(e)}), 500

# ----------------------------------------------------------------------------
# ADMIN PANEL - GELİŞMİŞ
# ----------------------------------------------------------------------------
@app.route('/admin')
@security_middleware
@limiter.limit("10 per minute")
def admin_panel():
    auth = request.args.get('auth')
    if auth != 'admin123':
        log_audit("Admin giriş sayfası", f"IP: {g.client_ip}")
        return '''
        <!DOCTYPE html>
        <html>
        <head><title>Admin Giriş</title></head>
        <body style="background:#0f172a;color:white;padding:50px;text-align:center;">
            <h1>🔐 Admin Panel</h1>
            <p>NEYI GORMEYE BEKLIYOSUN OROSPU COCUGU</p>
            <br>
            <div style="max-width:400px;margin:auto;background:#1e293b;padding:30px;border-radius:15px;">
                <p><strong>API ile Key Oluştur:</strong></p>
                <code style="background:#0f172a;padding:10px;border-radius:5px;display:block;margin:10px 0;">
                    /KEYACNABISIKDIBENI
                </code>
            </div>
        </body>
        </html>
        '''
    
    log_audit("Admin panele erişim", f"IP: {g.client_ip}")
    
    keys = Key.query.order_by(Key.created_at.desc()).all()
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    
    # DDoS istatistikleri
    blocked_count = len(ddos_protection.blocked_ips)
    suspicious_count = len(ddos_protection.suspicious_ips)
    
    # Kullanıcı istatistikleri
    active_users = len([k for k in keys if k.active and not k.is_expired()])
    vip_users = len([k for k in keys if k.is_vip() and k.active])
    free_users = len([k for k in keys if not k.is_vip() and k.active])
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel</title>
        <style>
            body {{ background:#0f172a; color:white; font-family:monospace; padding:20px; }}
            table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
            th, td {{ border: 1px solid #334155; padding: 10px; text-align: left; }}
            th {{ background: #1e293b; }}
            .vip {{ background: rgba(245,158,11,0.1); }}
            .free {{ background: rgba(100,116,139,0.1); }}
            .stats {{ display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }}
            .stat-box {{ background: #1e293b; padding: 15px; border-radius: 10px; min-width: 200px; }}
            .danger {{ color: #f87171; }}
            .warning {{ color: #fbbf24; }}
            .success {{ color: #34d399; }}
        </style>
    </head>
    <body>
        <h1>🔧 Admin Panel - Gelişmiş Yönetim</h1>
        
        <div class="stats">
            <div class="stat-box">
                <h3>📊 Sistem İstatistikleri</h3>
                <p>🚫 Engellenen IP'ler: <span class="danger">{blocked_count}</span></p>
                <p>⚠️ Şüpheli IP'ler: <span class="warning">{suspicious_count}</span></p>
                <p>👥 Aktif Kullanıcılar: <span class="success">{active_users}</span></p>
                <p>👑 VIP Kullanıcılar: {vip_users}</p>
                <p>🆓 Ücretsiz Kullanıcılar: {free_users}</p>
            </div>
        </div>
        
        <h2>📋 Mevcut Key'ler</h2>
        <table>
            <tr>
                <th>Key</th>
                <th>Plan</th>
                <th>Oluşturulma</th>
                <th>Bitiş</th>
                <th>Son Kullanım</th>
                <th>Kullanım</th>
                <th>Son IP</th>
                <th>Durum</th>
                <th>Sahip</th>
            </tr>
    '''
    
    for key in keys:
        status = '🟢 Aktif' if key.active and not key.is_expired() else '🔴 Pasif'
        row_class = 'vip' if key.plan != 'free' else 'free'
        
        expires = "Süresiz" if not key.expires_at else key.expires_at.strftime("%d/%m/%Y")
        created = key.created_at.strftime("%d/%m/%Y")
        last_used = key.last_used.strftime("%d/%m/%Y %H:%M") if key.last_used else "Hiç kullanılmadı"
        
        html += f'''
            <tr class="{row_class}">
                <td><code>{key.key}</code></td>
                <td>{key.plan.upper()}</td>
                <td>{created}</td>
                <td>{expires}</td>
                <td>{last_used}</td>
                <td>{key.usage_count}</td>
                <td><small>{key.last_ip or '-'}</small></td>
                <td>{status}</td>
                <td>{key.owner or '-'}</td>
            </tr>
        '''
    
    html += '''
        </table>
        
        <h2>📝 Son 100 Audit Log</h2>
        <table>
            <tr>
                <th>Zaman</th>
                <th>IP</th>
                <th>Action</th>
                <th>Details</th>
                <th>Key ID</th>
            </tr>
    '''
    
    for log in audit_logs:
        html += f'''
            <tr>
                <td>{log.timestamp.strftime("%H:%M:%S")}</td>
                <td><small>{log.ip_address}</small></td>
                <td>{log.action}</td>
                <td><small>{log.details[:50] if log.details else ''}</small></td>
                <td>{log.key_id or '-'}</td>
            </tr>
        '''
    
    html += '''
        </table>
    </body>
    </html>
    '''
    
    return html

# ----------------------------------------------------------------------------
# HATA SAYFALARI
# ----------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    log_audit("404 Sayfa bulunamadı", request.path)
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>404 - Sayfa Bulunamadı</title></head>
    <body style="background:#0f172a;color:white;text-align:center;padding:50px;">
        <h1>🔍 404 - Sayfa Bulunamadı</h1>
        <p><a href="/panel" style="color:#00e6ff;">🏠 Panel'e Dön</a></p>
    </body>
    </html>
    ''', 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "Rate limit exceeded",
        "message": "Çok fazla istek gönderdiniz. Lütfen daha sonra tekrar deneyin."
    }), 429

# ----------------------------------------------------------------------------
# BAŞLATMA - RENDER UYUMLU
# ----------------------------------------------------------------------------
if __name__ == '__main__':
    init_db()
    
    # Her gün audit log temizleme (60 günden eski)
    def clean_old_logs():
        with app.app_context():
            cutoff = datetime.now() - timedelta(days=60)
            old_logs = AuditLog.query.filter(AuditLog.timestamp < cutoff).delete()
            db.session.commit()
            if old_logs:
                print(f"[Cleanup] {old_logs} eski log temizlendi")
    
    # Temizleme thread'i
    cleanup_thread = threading.Thread(target=lambda: (
        time.sleep(86400),  # 24 saatte bir
        clean_old_logs()
    ), daemon=True)
    cleanup_thread.start()
    
    print("\n" + "="*60)
    print("ÖZSOY PANEL - GÜVENLİKLI & TÜM API'LER GÜNCELLENDİ")
    print("="*60)
    print(f"🔐 DDoS Koruması: AKTİF")
    print(f"👤 Kullanıcı Takip: AKTİF")
    print(f"📊 Audit Logging: AKTİF")
    print(f"📱 URL: http://127.0.0.1:5000")
    print(f"🔑 FREE Key: {SABIT_FREE_KEY}")
    print("="*60)
    print(f"📊 Toplam API: {len(APIS)}")
    print(f"🆓 Free API: {len([a for a in APIS.values() if a['plan'] == 'free'])}")
    print(f"👑 VIP API: {len([a for a in APIS.values() if a['plan'] == 'vip'])}")
    print("="*60)
    print("\n📋 API KATEGORİLERİ:")
    print("1. TC ve GSM API'leri (Zyrdaware)")
    print("2. Plaka API'leri (PlakaF3)")
    print("3. Papara API'leri")
    print("4. Eczane API'leri")
    print("5. Seri No API'leri")
    print("6. Vergi API'leri")
    print("7. Phishing API'leri")
    print("8. Panel API'leri (Kapsamlı)")
    print("="*60 + "\n")
    
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    
    app.run(
        debug=debug_mode,
        host='0.0.0.0',
        port=port,
        threaded=True
)
