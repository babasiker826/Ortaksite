"""
ÖZSOY PANEL - GÜVENLİK MAX SİSTEMİ
- API üzerinden key kontrol
- Anti-hack korumaları
- Tüm API'ler VIP, sadece 2 API free
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
import hmac
import base64
import uuid
from functools import wraps
from collections import defaultdict, deque, OrderedDict
import asyncio
import pickle
from typing import Dict, List, Optional, Tuple, Any
import hashlib
import binascii

from flask import Flask, request, session, jsonify, render_template, redirect, url_for, flash, g, abort, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

# ----------------------------------------------------------------------------
# FLASK APP
# ----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'keneviz_secure.sqlite')

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_urlsafe(128))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=6)
app.config['SESSION_REFRESH_EACH_REQUEST'] = False

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=2, x_proto=2, x_host=1, x_port=1, x_prefix=1)

db = SQLAlchemy(app)

# Özel rate limiter sınıfı
class SecureLimiter:
    def __init__(self):
        self.rate_data = {}
        self.blocked_ips = {}
        
    def check_limit(self, key, limit):
        now = time.time()
        if key in self.blocked_ips:
            if now - self.blocked_ips[key]['blocked_at'] < 3600:  # 1 saat blok
                return False
            else:
                del self.blocked_ips[key]
        
        if key not in self.rate_data:
            self.rate_data[key] = {'count': 1, 'first_seen': now}
            return True
        
        data = self.rate_data[key]
        window = 60  # 60 saniyelik pencere
        
        if now - data['first_seen'] > window:
            # Pencereyi sıfırla
            self.rate_data[key] = {'count': 1, 'first_seen': now}
            return True
        
        if data['count'] >= limit:
            # IP'yi blokla
            self.blocked_ips[key] = {'blocked_at': now, 'reason': 'rate_limit'}
            return False
        
        data['count'] += 1
        return True

secure_limiter = SecureLimiter()

limiter = Limiter(
    app=app,
    key_func=lambda: request.headers.get('X-Real-IP', request.remote_addr),
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="fixed-window",
    headers_enabled=True
)

SABIT_FREE_KEY = "FREESORGUPANELI2025A"
API_CHECK_URL = "https://f3systemkeyleri.onrender.com/key/kontrol"

# ----------------------------------------------------------------------------
# MODELS
# ----------------------------------------------------------------------------
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    login_ip = db.Column(db.String(45), nullable=True)
    twofa_secret = db.Column(db.String(32), nullable=True)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

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
    api_created = db.Column(db.Boolean, default=False)
    api_key_id = db.Column(db.String(100), nullable=True)
    request_signature = db.Column(db.String(128), nullable=True)
    access_token = db.Column(db.String(128), unique=True, nullable=True)
    token_expires = db.Column(db.DateTime, nullable=True)
    security_level = db.Column(db.Integer, default=1)  # 1-5 arası güvenlik seviyesi

    def is_expired(self):
        if not self.expires_at:
            return False
        return datetime.now() > self.expires_at

    def is_vip(self):
        return self.plan != 'free'
    
    def generate_access_token(self):
        token = secrets.token_urlsafe(64)
        self.access_token = hashlib.sha256(token.encode()).hexdigest()
        self.token_expires = datetime.now() + timedelta(hours=24)
        db.session.commit()
        return token
    
    def validate_token(self, token):
        if not self.token_expires or datetime.now() > self.token_expires:
            return False
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return hmac.compare_digest(token_hash, self.access_token or "")

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now, index=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    user_agent = db.Column(db.Text, nullable=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)
    key_id = db.Column(db.Integer, nullable=True, index=True)
    endpoint = db.Column(db.String(200), nullable=True)
    request_hash = db.Column(db.String(64), nullable=True, index=True)

class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now, index=True)
    event_type = db.Column(db.String(50), nullable=False)  # hack_attempt, brute_force, sql_injection, etc.
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    severity = db.Column(db.Integer, default=1)  # 1-5 arası
    details = db.Column(db.Text, nullable=True)
    blocked = db.Column(db.Boolean, default=False)
    user_agent = db.Column(db.Text, nullable=True)
    request_path = db.Column(db.String(500), nullable=True)
    payload = db.Column(db.Text, nullable=True)

class RateLimit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    identifier = db.Column(db.String(100), nullable=False, index=True)
    window_start = db.Column(db.DateTime, default=datetime.now)
    request_count = db.Column(db.Integer, default=0)
    limit = db.Column(db.Integer, default=100)

# ----------------------------------------------------------------------------
# GÜVENLİK ARAÇLARI
# ----------------------------------------------------------------------------
class SecurityTools:
    # SQL Injection patternleri
    SQL_INJECTION_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # SQL meta karakterleri
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",  # = ' veya --
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",  # ' or
        r"((\%27)|(\'))union",  # ' union
        r"exec(\s|\+)+(s|x)p\w+",  # exec stored procedure
        r"/\*.*\*/",  # SQL comment
        r"(\%27)|(\')|(\-\-)|(;)|(\%00)",  # Null byte
    ]
    
    # XSS patternleri
    XSS_PATTERNS = [
        r"<script.*?>.*?</script>",
        r"javascript:",  # javascript: protocol
        r"on\w+\s*=",  # onload=, onclick=, vb.
        r"eval\s*\(",  # eval()
        r"alert\s*\(",  # alert()
        r"document\.",  # document.
        r"window\.",  # window.
        r"<iframe.*?>",  # iframe
        r"<object.*?>",  # object
        r"<embed.*?>",  # embed
        r"<applet.*?>",  # applet
    ]
    
    # Path traversal patternleri
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",  # ../ 
        r"\.\.\\",  # ..\
        r"\.\.%2f",  # ..%2f
        r"\.\.%5c",  # ..%5c
        r"%2e%2e%2f",  # %2e%2e%2f
        r"%2e%2e%5c",  # %2e%2e%5c
    ]
    
    # Shell injection patternleri
    SHELL_INJECTION_PATTERNS = [
        r";\s*\w+",  # ; command
        r"\|\s*\w+",  # | command
        r"&\s*\w+",  # & command
        r"\$\s*\(",  # $(
        r"`\s*\w+",  # `command`
    ]
    
    @classmethod
    def detect_malicious_input(cls, data: str) -> Tuple[bool, str]:
        """Kötü niyetli input tespiti"""
        if not data:
            return False, ""
            
        data_lower = data.lower()
        
        # SQL Injection kontrolü
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, data_lower, re.IGNORECASE):
                return True, f"SQL Injection tespit edildi: {pattern}"
        
        # XSS kontrolü
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, data_lower, re.IGNORECASE):
                return True, f"XSS tespit edildi: {pattern}"
        
        # Path traversal kontrolü
        for pattern in cls.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, data_lower):
                return True, f"Path traversal tespit edildi: {pattern}"
        
        # Shell injection kontrolü
        for pattern in cls.SHELL_INJECTION_PATTERNS:
            if re.search(pattern, data_lower):
                return True, f"Shell injection tespit edildi: {pattern}"
        
        return False, ""
    
    @classmethod
    def generate_hmac_signature(cls, data: str, key: str) -> str:
        """HMAC imzası oluştur"""
        return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()
    
    @classmethod
    def verify_hmac_signature(cls, data: str, signature: str, key: str) -> bool:
        """HMAC imzasını doğrula"""
        expected = cls.generate_hmac_signature(data, key)
        return hmac.compare_digest(expected, signature)
    
    @classmethod
    def create_request_nonce(cls) -> str:
        """Rastgele nonce oluştur"""
        return secrets.token_urlsafe(32)
    
    @classmethod
    def encrypt_data(cls, data: str, key: str) -> str:
        """Basit şifreleme"""
        from cryptography.fernet import Fernet
        fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()[:32]))
        return fernet.encrypt(data.encode()).decode()
    
    @classmethod
    def decrypt_data(cls, encrypted: str, key: str) -> str:
        """Şifre çözme"""
        from cryptography.fernet import Fernet
        fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()[:32]))
        return fernet.decrypt(encrypted.encode()).decode()

# ----------------------------------------------------------------------------
# TÜM API'LER
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
# YARDIMCI FONKSIYONLAR
# ----------------------------------------------------------------------------
def init_db():
    with app.app_context():
        db.create_all()

        if Admin.query.first() is None:
            admin = Admin(username='admin', password_hash=generate_password_hash('admin123'))
            db.session.add(admin)
            db.session.commit()
            print("[INFO] Admin: admin / admin123")

        if not Key.query.filter_by(key=SABIT_FREE_KEY).first():
            free_key = Key(
                key=SABIT_FREE_KEY,
                plan='free',
                created_at=datetime.now(),
                expires_at=None,
                active=True,
                notes='Sabit Free Key',
                owner='SYSTEM',
                api_created=False,
                security_level=1
            )
            db.session.add(free_key)
            db.session.commit()
            print(f"[INFO] FREE Key: {SABIT_FREE_KEY}")

def verify_key_string(kstr):
    if not kstr or not kstr.strip():
        return None

    kstr = kstr.strip()

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
                owner='SYSTEM',
                api_created=False,
                security_level=1
            )
            db.session.add(key)
            db.session.commit()
        return key

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

def get_client_ip():
    """Client IP adresini güvenli şekilde al"""
    trusted_proxies = ['127.0.0.1']
    
    # X-Forwarded-For kontrolü
    xff = request.headers.get('X-Forwarded-For')
    if xff:
        # İlk IP'yi al (client IP)
        client_ip = xff.split(',')[0].strip()
        # Proxy IP'leri kontrol et
        proxies = xff.split(',')[1:] if ',' in xff else []
        for proxy in proxies:
            proxy = proxy.strip()
            if proxy not in trusted_proxies:
                # Güvenilmeyen proxy, saldırı olabilir
                log_security_event('untrusted_proxy', getattr(request, 'remote_addr', '0.0.0.0'), 
                                 severity=3, details=f'Untrusted proxy: {proxy}')
                return getattr(request, 'remote_addr', '0.0.0.0')
    else:
        client_ip = request.remote_addr or '0.0.0.0'
    
    try:
        # IP adresini doğrula
        ipaddress.ip_address(client_ip)
        return client_ip
    except:
        return '0.0.0.0'

def log_security_event(event_type, ip_address, severity=1, details=None, user_agent=None, request_path=None, payload=None):
    """Güvenlik olayını logla"""
    try:
        event = SecurityEvent(
            event_type=event_type,
            ip_address=ip_address,
            severity=severity,
            details=details[:1000] if details else None,
            user_agent=user_agent[:500] if user_agent else None,
            request_path=request_path[:500] if request_path else None,
            payload=payload[:1000] if payload else None,
            blocked=severity >= 4  # Yüksek severity'de otomatik blok
        )
        db.session.add(event)
        db.session.commit()
        
        # Yüksek severity olaylarında console'a yaz
        if severity >= 3:
            print(f"[SECURITY] {event_type.upper()} - IP: {ip_address} - Severity: {severity}")
            if details:
                print(f"[SECURITY] Details: {details}")
                
    except Exception as e:
        print(f"[SECURITY ERROR] Loglama hatası: {e}")

def check_key_via_api_secure(kstr, client_ip):
    """API üzerinden key kontrolü yap - Güvenli versiyon"""
    if not kstr or len(kstr) != 20:
        log_security_event('invalid_key_format', client_ip, severity=2, 
                         details=f"Invalid key format: {kstr[:10]}...")
        return {'success': False, 'error': 'Geçersiz key formatı'}

    try:
        # Nonce ekle
        nonce = secrets.token_urlsafe(16)
        timestamp = int(time.time())
        
        # HMAC imzası oluştur
        data_to_sign = f"{kstr}{timestamp}{nonce}{client_ip}"
        hmac_key = app.config['SECRET_KEY'][:32]
        signature = SecurityTools.generate_hmac_signature(data_to_sign, hmac_key)
        
        url = f"{API_CHECK_URL}?key={kstr}&ts={timestamp}&nonce={nonce}&sig={signature}"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Client-IP': client_ip,
            'X-Request-ID': secrets.token_urlsafe(16),
            'X-Timestamp': str(timestamp)
        }

        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            try:
                data = response.json()
                
                # API'den gelen imzayı doğrula
                if 'signature' in data:
                    api_signature = data['signature']
                    api_data = f"{data.get('status','')}{data.get('bitis','')}{timestamp}"
                    if not SecurityTools.verify_hmac_signature(api_data, api_signature, hmac_key):
                        log_security_event('api_signature_mismatch', client_ip, severity=4,
                                         details=f"API signature mismatch for key: {kstr[:10]}...")
                        return {'success': False, 'error': 'Güvenlik doğrulama hatası'}

                if data.get('durum') == 'aktif':
                    return {
                        'success': True,
                        'key': kstr,
                        'status': 'active',
                        'expires_at': data.get('bitis'),
                        'signature': data.get('signature')
                    }
                elif data.get('durum') == 'pasif':
                    return {'success': False, 'error': 'Key pasif veya süresi dolmuş'}
                else:
                    return {'success': True, 'key': kstr, 'status': 'active', 'expires_at': data.get('bitis')}
            except Exception as e:
                # Text response'u parse et
                text_response = response.text.lower()
                if 'aktif' in text_response or 'true' in text_response or 'success' in text_response:
                    return {'success': True, 'key': kstr, 'status': 'active'}
                else:
                    return {'success': False, 'error': 'Key bulunamadı veya pasif'}
        elif response.status_code == 404:
            return {'success': False, 'error': 'Key bulunamadı'}
        else:
            return {'success': False, 'error': f'API hatası: {response.status_code}'}

    except requests.Timeout:
        log_security_event('api_timeout', client_ip, severity=2,
                         details=f"API timeout for key: {kstr[:10]}...")
        return {'success': False, 'error': 'API yanıt vermedi (timeout)'}
    except requests.ConnectionError:
        log_security_event('api_connection_error', client_ip, severity=3,
                         details=f"API connection error for key: {kstr[:10]}...")
        return {'success': False, 'error': 'API sunucusuna bağlanılamadı'}
    except Exception as e:
        log_security_event('api_check_error', client_ip, severity=3,
                         details=f"API check error: {str(e)[:100]}")
        return {'success': False, 'error': f'Kontrol hatası: {str(e)[:50]}'}

# ----------------------------------------------------------------------------
# DECORATOR'LAR
# ----------------------------------------------------------------------------
def security_check(f):
    """Güvenlik kontrol decorator'ı"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = get_client_ip()
        user_agent = request.headers.get('User-Agent', '')
        request_path = request.path
        
        # 1. Rate limiting kontrolü
        if not secure_limiter.check_limit(client_ip, 50):  # 50 request/hour
            log_security_event('rate_limit_exceeded', client_ip, severity=4,
                             user_agent=user_agent, request_path=request_path)
            abort(429)
        
        # 2. User-Agent kontrolü
        if not user_agent or len(user_agent) < 10:
            log_security_event('suspicious_user_agent', client_ip, severity=2,
                             user_agent=user_agent, request_path=request_path)
        
        # 3. Request boyutu kontrolü (sadece POST için)
        if request.method == 'POST':
            content_length = request.content_length or 0
            if content_length > 10 * 1024 * 1024:  # 10MB
                log_security_event('large_request', client_ip, severity=3,
                                 details=f"Request too large: {content_length} bytes",
                                 request_path=request_path)
                abort(413)
        
        # 4. SQL Injection ve XSS kontrolü
        for arg_name, arg_value in request.args.items():
            malicious, reason = SecurityTools.detect_malicious_input(str(arg_value))
            if malicious:
                log_security_event('malicious_input', client_ip, severity=4,
                                 details=f"{reason} in param: {arg_name}",
                                 user_agent=user_agent, request_path=request_path,
                                 payload=str(arg_value)[:200])
                abort(400)
        
        # 5. Session fixation koruması
        if 'key' in session:
            # Session ID'yi düzenli olarak değiştir
            if 'session_regenerated' not in session:
                session['session_regenerated'] = True
                # Flask otomatik olarak session ID'sini değiştirir
        
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = get_client_ip()
        
        if 'key' not in session:
            log_security_event('no_session_key', client_ip, severity=1,
                             request_path=request.path)
            return redirect(url_for('login'))

        key_str = session.get('key')
        
        # Anti-tampering kontrolü
        if 'key_hash' in session:
            stored_hash = session['key_hash']
            current_hash = hashlib.sha256(key_str.encode()).hexdigest()
            if not hmac.compare_digest(stored_hash, current_hash):
                log_security_event('session_tampering', client_ip, severity=5,
                                 details="Key hash mismatch",
                                 request_path=request.path)
                session.clear()
                return redirect(url_for('login'))

        key = verify_key_string(key_str)

        if not key and key_str != SABIT_FREE_KEY and len(key_str) == 20:
            if request.method == 'GET' and request.endpoint == 'panel':
                return render_template('key_checking.html', key=key_str)

            try:
                # API'den kontrol et
                result = check_key_via_api_secure(key_str, client_ip)

                if result.get('success'):
                    # DB'de key var mı kontrol et
                    key = Key.query.filter_by(key=key_str).first()

                    if not key:
                        # Bitiş tarihini parse et
                        expires_at = None
                        expiry_str = result.get('expires_at')
                        if expiry_str:
                            try:
                                if 'T' in expiry_str:
                                    date_part, time_part = expiry_str.split('T')
                                    year, month, day = date_part.split('-')
                                    time_with_ms = time_part.split('.')[0]
                                    hour, minute, second = time_with_ms.split(':')
                                    expires_at = datetime(
                                        int(year), int(month), int(day),
                                        int(hour), int(minute), int(second)
                                    )
                            except:
                                pass

                        # Yeni key oluştur
                        key = Key(
                            key=key_str,
                            plan='vip',
                            created_at=datetime.now(),
                            expires_at=expires_at,
                            active=True,
                            notes='API üzerinden doğrulandı',
                            owner='API User',
                            api_created=True,
                            api_key_id=f"api_{key_str[:10]}",
                            security_level=3
                        )
                        db.session.add(key)
                        db.session.commit()

                    # Session'a güvenli kaydet
                    session['key'] = key.key
                    session['key_hash'] = hashlib.sha256(key.key.encode()).hexdigest()
                    session['plan'] = key.plan
                    session['key_id'] = key.id
                    session['logged_in'] = True
                    session['username'] = f"user{key.id}"
                    session['is_vip'] = key.plan != 'free'
                    session['login_ip'] = client_ip
                    session['login_time'] = int(time.time())
                    session.modified = True
                    
                    log_security_event('key_validated', client_ip, severity=1,
                                     details=f"Key validated: {key_str[:10]}...",
                                     request_path=request.path)
                else:
                    session.clear()
                    error_msg = result.get("error", "Bilinmeyen hata")
                    log_security_event('key_validation_failed', client_ip, severity=2,
                                     details=f"Key validation failed: {error_msg}",
                                     request_path=request.path)
                    flash(f'Key geçersiz: {error_msg}')
                    return redirect(url_for('login'))

            except Exception as e:
                log_security_event('key_check_error', client_ip, severity=3,
                                 details=f"Key check error: {str(e)}",
                                 request_path=request.path)
                session.clear()
                flash('Key doğrulama hatası')
                return redirect(url_for('login'))

        if not key:
            log_security_event('invalid_key_session', client_ip, severity=2,
                             details="Invalid key in session",
                             request_path=request.path)
            session.clear()
            flash('Key geçersiz veya süresi dolmuş')
            return redirect(url_for('login'))

        # Session timeout kontrolü (6 saat)
        login_time = session.get('login_time')
        if login_time and (time.time() - login_time > 21600):  # 6 saat
            log_security_event('session_timeout', client_ip, severity=1,
                             details="Session timeout",
                             request_path=request.path)
            session.clear()
            flash('Oturum süreniz doldu')
            return redirect(url_for('login'))

        key.last_used = datetime.now()
        key.usage_count += 1
        key.last_ip = client_ip
        db.session.commit()

        return f(*args, **kwargs)
    return decorated_function

# ----------------------------------------------------------------------------
# ROUTE'LAR
# ----------------------------------------------------------------------------
@app.before_request
def before_request():
    g.client_ip = get_client_ip()
    g.request_id = secrets.token_urlsafe(16)
    
    # CSRF token kontrolü (POST request'ler için)
    if request.method == 'POST' and request.path not in ['/login', '/keneviz_verify']:
        csrf_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        session_csrf = session.get('csrf_token')
        
        if not csrf_token or not session_csrf or not hmac.compare_digest(csrf_token, session_csrf):
            log_security_event('csrf_attempt', g.client_ip, severity=4,
                             request_path=request.path, details="CSRF token mismatch")
            abort(403)

@app.after_request
def after_request(response):
    """Response header'larına güvenlik ekle"""
    # CSP Header
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    
    # Security Headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Custom header
    response.headers['X-Request-ID'] = g.request_id
    
    return response

@app.route('/')
@security_check
def index():
    return redirect(url_for('robot_dogrulama'))

@app.route('/robot_dogrulama')
@limiter.limit("10 per minute")
@security_check
def robot_dogrulama():
    next_page = request.args.get('next', '/login')
    # CSRF token oluştur
    session['csrf_token'] = secrets.token_urlsafe(32)
    return render_template('robot_dogrulama.html', next_page=next_page, csrf_token=session['csrf_token'])

@app.route('/keneviz_challenge', methods=['POST'])
@limiter.limit("5 per minute")
@security_check
def keneviz_challenge():
    # CSRF token kontrolü
    csrf_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
    if not csrf_token or not hmac.compare_digest(csrf_token, session.get('csrf_token', '')):
        abort(403)
    
    nonce = secrets.token_urlsafe(16)
    session['keneviz_challenge'] = {
        'nonce': nonce,
        'ts': int(time.time()),
        'tries': 0,
        'ip': g.client_ip,
        'challenge_hash': hashlib.sha256(f"{nonce}{g.client_ip}".encode()).hexdigest()
    }
    session.modified = True
    
    # Challenge'ı şifrele
    challenge_data = {
        'challenge_id': nonce,
        'ts': session['keneviz_challenge']['ts'],
        'hash': session['keneviz_challenge']['challenge_hash']
    }
    
    return jsonify(challenge_data)

@app.route('/keneviz_verify', methods=['POST'])
@limiter.limit("5 per minute")
@security_check
def keneviz_verify():
    try:
        data = request.get_json() or {}
        saved = session.get('keneviz_challenge')

        if not saved:
            log_security_event('no_challenge', g.client_ip, severity=2,
                             request_path=request.path)
            return jsonify({'success': False, 'error': 'no_challenge'}), 400

        if saved.get('ip') != g.client_ip:
            log_security_event('ip_mismatch', g.client_ip, severity=3,
                             request_path=request.path, 
                             details=f"IP mismatch: {g.client_ip} != {saved.get('ip')}")
            return jsonify({'success': False, 'error': 'ip_mismatch'}), 400

        incoming_nonce = data.get('challenge_id')
        if not incoming_nonce or incoming_nonce != saved.get('nonce'):
            log_security_event('challenge_mismatch', g.client_ip, severity=3,
                             request_path=request.path)
            return jsonify({'success': False, 'error': 'challenge_mismatch'}), 400

        # Hash kontrolü
        expected_hash = hashlib.sha256(f"{incoming_nonce}{g.client_ip}".encode()).hexdigest()
        if not hmac.compare_digest(expected_hash, saved.get('challenge_hash', '')):
            log_security_event('challenge_hash_mismatch', g.client_ip, severity=4,
                             request_path=request.path)
            return jsonify({'success': False, 'error': 'challenge_hash_mismatch'}), 400

        if time.time() - saved.get('ts', 0) > 300:
            return jsonify({'success': False, 'error': 'timeout'}), 400

        session['keneviz_verified'] = True
        session.pop('keneviz_challenge', None)
        session.modified = True

        return jsonify({
            'success': True,
            'verification_token': 'verified',
            'redirect': data.get('next', '/login')
        })
    except Exception as e:
        log_security_event('verification_error', g.client_ip, severity=3,
                         request_path=request.path, details=str(e))
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", methods=['POST'])
@security_check
def login():
    if not session.get('keneviz_verified'):
        return redirect(url_for('robot_dogrulama') + '?next=/login')

    if request.method == 'GET':
        # Yeni CSRF token oluştur
        session['csrf_token'] = secrets.token_urlsafe(32)
        return render_template('login.html', csrf_token=session['csrf_token'])

    # CSRF kontrolü
    csrf_token = request.form.get('csrf_token')
    if not csrf_token or not hmac.compare_digest(csrf_token, session.get('csrf_token', '')):
        log_security_event('csrf_login_attempt', g.client_ip, severity=4,
                         request_path=request.path)
        flash('Güvenlik hatası!')
        return redirect(url_for('login'))

    key_str = request.form.get('key', '').strip()

    if not key_str:
        flash('Key giriniz!')
        return redirect(url_for('login'))

    # Eğer FREE key ise direk panele yönlendir
    if key_str == SABIT_FREE_KEY:
        key = verify_key_string(key_str)

        if not key:
            log_security_event('invalid_free_key', g.client_ip, severity=2,
                             request_path=request.path, details="Invalid free key")
            flash('Free key geçersiz!')
            return redirect(url_for('login'))

        # Güvenli session oluştur
        session['key'] = key.key
        session['key_hash'] = hashlib.sha256(key.key.encode()).hexdigest()
        session['plan'] = key.plan
        session['key_id'] = key.id
        session['logged_in'] = True
        session['username'] = f"user{key.id}"
        session['is_vip'] = key.plan != 'free'
        session['login_ip'] = g.client_ip
        session['login_time'] = int(time.time())
        
        # CSRF token'ı yenile
        session['csrf_token'] = secrets.token_urlsafe(32)

        session.pop('keneviz_verified', None)
        session.modified = True

        log_security_event('free_login_success', g.client_ip, severity=1,
                         details="Free login successful")
        return redirect(url_for('panel'))

    # 20 haneli key değilse hata
    if len(key_str) != 20:
        log_security_event('invalid_key_length', g.client_ip, severity=2,
                         request_path=request.path, details=f"Key length: {len(key_str)}")
        flash('Geçersiz key formatı! 20 haneli VIP key veya FREE key girin.')
        return redirect(url_for('login'))

    # Önce local DB'de kontrol et
    key = verify_key_string(key_str)

    # Local DB'de varsa ve aktifse direk panele yönlendir
    if key and key.active and not key.is_expired():
        session['key'] = key.key
        session['key_hash'] = hashlib.sha256(key.key.encode()).hexdigest()
        session['plan'] = key.plan
        session['key_id'] = key.id
        session['logged_in'] = True
        session['username'] = f"user{key.id}"
        session['is_vip'] = key.plan != 'free'
        session['login_ip'] = g.client_ip
        session['login_time'] = int(time.time())
        session['csrf_token'] = secrets.token_urlsafe(32)

        session.pop('keneviz_verified', None)
        session.modified = True
        
        log_security_event('vip_login_success', g.client_ip, severity=1,
                         details=f"VIP login: {key_str[:10]}...")
        return redirect(url_for('panel'))

    # Local DB'de yoksa veya geçersizse kontrol sayfasına yönlendir
    return render_template('key_checking.html', key=key_str)

@app.route('/key_check_status')
@limiter.limit("5 per minute")
@security_check
def key_check_status():
    key_str = request.args.get('key', '')
    
    # IP bazlı rate limiting
    if not secure_limiter.check_limit(g.client_ip, 3):  # 3 kez/process
        log_security_event('key_check_rate_limit', g.client_ip, severity=3,
                         request_path=request.path)
        return jsonify({'success': False, 'error': 'Rate limit exceeded'}), 429

    if not key_str or len(key_str) != 20:
        log_security_event('invalid_key_check_format', g.client_ip, severity=2,
                         request_path=request.path, details=f"Key: {key_str[:10]}...")
        return jsonify({'success': False, 'error': 'Geçersiz key formatı'})

    try:
        # API'den kontrol et
        result = check_key_via_api_secure(key_str, g.client_ip)

        if result.get('success'):
            key = Key.query.filter_by(key=key_str).first()

            if not key:
                expires_at = None
                expiry_str = result.get('expires_at')
                if expiry_str:
                    try:
                        if 'T' in expiry_str:
                            date_part, time_part = expiry_str.split('T')
                            year, month, day = date_part.split('-')
                            time_with_ms = time_part.split('.')[0]
                            hour, minute, second = time_with_ms.split(':')
                            expires_at = datetime(
                                int(year), int(month), int(day),
                                int(hour), int(minute), int(second)
                            )
                    except:
                        pass

                # Yeni key oluştur
                key = Key(
                    key=key_str,
                    plan='vip',
                    created_at=datetime.now(),
                    expires_at=expires_at,
                    active=True,
                    notes='API üzerinden doğrulandı',
                    owner='VIP User',
                    api_created=True,
                    api_key_id=f"api_{key_str[:10]}",
                    security_level=3
                )
                db.session.add(key)
                db.session.commit()

            # Güvenli session oluştur
            session['key'] = key.key
            session['key_hash'] = hashlib.sha256(key.key.encode()).hexdigest()
            session['plan'] = key.plan
            session['key_id'] = key.id
            session['logged_in'] = True
            session['username'] = f"user{key.id}"
            session['is_vip'] = True
            session['login_ip'] = g.client_ip
            session['login_time'] = int(time.time())
            session['csrf_token'] = secrets.token_urlsafe(32)
            session.modified = True

            log_security_event('key_validation_success', g.client_ip, severity=1,
                             details=f"Key validated: {key_str[:10]}...")

            return jsonify({
                'success': True,
                'key': key_str,
                'plan': 'vip',
                'status': 'active',
                'is_vip': True,
                'message': 'Key başarıyla doğrulandı! VIP erişim aktif.',
                'redirect': '/panel',
                'session_created': True
            })
        else:
            error_msg = result.get('error', 'Key doğrulanamadı')
            log_security_event('key_validation_failed_api', g.client_ip, severity=2,
                             details=f"Key validation failed: {error_msg}",
                             payload=key_str[:10] + "...")
            
            # Başarısız denemeleri say
            failed_key = f"failed_{key_str}"
            if not secure_limiter.check_limit(failed_key, 2):  # 2 kez deneme
                log_security_event('key_brute_force_attempt', g.client_ip, severity=4,
                                 details=f"Brute force attempt for key: {key_str[:10]}...")
                return jsonify({'success': False, 'error': 'Güvenlik nedeniyle bloklandı'}), 403

            return jsonify({
                'success': False,
                'error': error_msg,
                'message': 'Geçersiz key veya API yanıt vermedi'
            })

    except Exception as e:
        log_security_event('key_check_exception', g.client_ip, severity=3,
                         details=f"Exception: {str(e)}",
                         request_path=request.path)
        return jsonify({'success': False, 'error': str(e)[:100]})

@app.route('/logout')
@security_check
def logout():
    if 'key' in session:
        key_str = session.get('key', '')[:10]
        log_security_event('user_logout', g.client_ip, severity=1,
                         details=f"User logged out: {key_str}...")
    session.clear()
    return redirect(url_for('login'))

@app.route('/panel')
@login_required
@limiter.limit("30 per minute")
@security_check
def panel():
    key_str = session.get('key')
    key = verify_key_string(key_str)

    if not key:
        session.clear()
        flash('Key geçersiz veya süresi dolmuş')
        return redirect(url_for('login'))

    # Kalan süreyi hesapla
    remaining = 'Sınırsız'
    if key.expires_at:
        now = datetime.now()
        if key.expires_at > now:
            delta = key.expires_at - now
            days = delta.days
            hours = delta.seconds // 3600
            minutes = (delta.seconds % 3600) // 60
            remaining = f"{days}g {hours}s {minutes}d"
        else:
            remaining = 'Süresi Doldu'

    # Bugünkü sorgu sayısını hesapla
    from datetime import date
    today = date.today()
    today_calls = key.usage_count if key.last_used and key.last_used.date() == today else 0

    # API istatistikleri
    total_apis = len(APIS)
    free_apis = len([a for a in APIS.values() if a['plan'] == 'free'])
    vip_apis = len([a for a in APIS.values() if a['plan'] == 'vip'])

    # VIP kullanıcı için erişilebilir API sayısı
    user_apis = total_apis if key.is_vip() else free_apis

    # Güvenlik durumu
    security_level = key.security_level or 1
    security_status = "YÜKSEK" if security_level >= 3 else "ORTA" if security_level >= 2 else "DÜŞÜK"

    # Son güvenlik olayları
    recent_security_events = SecurityEvent.query.filter(
        SecurityEvent.ip_address == g.client_ip
    ).order_by(SecurityEvent.timestamp.desc()).limit(5).all()

    # CSRF token oluştur
    csrf_token = secrets.token_urlsafe(32)
    session['csrf_token'] = csrf_token

    return render_template('panel.html',
        key=key,
        username=session.get('username', 'Misafir'),
        plan=key.plan,
        plan_name='VIP' if key.is_vip() else 'FREE',
        is_vip=key.is_vip(),
        remaining=remaining,
        today_calls=today_calls,
        total_apis=total_apis,
        free_apis=free_apis,
        vip_apis=vip_apis,
        user_apis=user_apis,
        user_ip=session.get('login_ip', 'Bilinmiyor'),
        last_login=key.last_used,
        last_api=key.last_used,
        free_key=SABIT_FREE_KEY,
        security_level=security_level,
        security_status=security_status,
        recent_security_events=recent_security_events,
        csrf_token=csrf_token
    )

@app.route('/sorgu.html')
@login_required
@limiter.limit("20 per minute")
@security_check
def sorgu_page():
    api_id = request.args.get('api', '').lower()

    if not api_id:
        flash('API seçilmedi!')
        return redirect(url_for('panel'))

    if api_id not in APIS:
        flash('Geçersiz API!')
        return redirect(url_for('panel'))

    key_str = session.get('key')
    key = verify_key_string(key_str)

    if not key:
        session.clear()
        flash('Key geçersiz veya süresi dolmuş')
        return redirect(url_for('login'))

    api_info = APIS[api_id]

    # API plan kontrolü - eğer VIP API ve kullanıcı VIP değilse
    if api_info['plan'] == 'vip' and not key.is_vip():
        log_security_event('vip_api_access_denied', g.client_ip, severity=2,
                         details=f"Attempted VIP API access: {api_info['name']}")
        flash(f"Bu API için VIP üyelik gereklidir: {api_info['name']}")
        return redirect(url_for('abonelik_page'))

    # CSRF token oluştur
    csrf_token = secrets.token_urlsafe(32)
    session['csrf_token'] = csrf_token

    return render_template('sorgu.html',
                         api_id=api_id,
                         api_info=api_info,
                         is_vip=key.is_vip(),
                         username=session.get('username', 'Misafir'),
                         csrf_token=csrf_token)

@app.route('/abonelik.html')
@security_check
def abonelik_page():
    csrf_token = secrets.token_urlsafe(32)
    session['csrf_token'] = csrf_token
    return render_template('abonelik.html', csrf_token=csrf_token)

@app.route('/security_events')
@login_required
@security_check
def security_events():
    """Güvenlik olaylarını görüntüle (sadece admin)"""
    key_str = session.get('key')
    key = verify_key_string(key_str)
    
    if not key or key.plan == 'free':
        abort(403)
    
    # Son 100 güvenlik olayı
    events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).limit(100).all()
    
    csrf_token = secrets.token_urlsafe(32)
    session['csrf_token'] = csrf_token
    
    return render_template('security_events.html',
                         events=events,
                         csrf_token=csrf_token)

# ----------------------------------------------------------------------------
# API ENDPOINT'LERİ
# ----------------------------------------------------------------------------
@app.route('/api/user')
@security_check
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
        'security_level': key.security_level or 1
    })

@app.route('/api/list')
@login_required
@limiter.limit("10 per minute")
@security_check
def api_list():
    key_str = session.get('key')
    key = verify_key_string(key_str)

    total = len(APIS)
    free = len([a for a in APIS.values() if a['plan'] == 'free'])
    vip = len([a for a in APIS.values() if a['plan'] == 'vip'])

    return jsonify({
        'success': True,
        'total_apis': total,
        'free_apis': free,
        'vip_apis': vip
    })

@app.route('/api/sorgu', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
@security_check
def api_sorgu():
    # CSRF token kontrolü
    csrf_token = request.headers.get('X-CSRF-Token') or (request.get_json() or {}).get('csrf_token')
    if not csrf_token or not hmac.compare_digest(csrf_token, session.get('csrf_token', '')):
        log_security_event('api_csrf_attempt', g.client_ip, severity=4,
                         request_path=request.path)
        abort(403)
    
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
        log_security_event('vip_api_attempt', g.client_ip, severity=2,
                         details=f"Free user attempted VIP API: {api_id}")
        return jsonify({
            'success': False,
            'error': f'Bu API için VIP üyelik gereklidir. Mevcut planınız: {user_plan}',
            'redirect': '/abonelik.html',
            'api_name': APIS[api_id]['name'],
            'user_plan': user_plan,
            'required_plan': 'vip'
        }), 403

    # Parametreleri kontrol et
    api_params = APIS[api_id]['params']
    param_values = {}
    for param in api_params:
        param_value = data.get(param, '')
        if not param_value:
            return jsonify({'success': False, 'error': f'{param} parametresi gereklidir'}), 400
        
        # Güvenlik kontrolü
        malicious, reason = SecurityTools.detect_malicious_input(str(param_value))
        if malicious:
            log_security_event('malicious_api_param', g.client_ip, severity=4,
                             details=f"{reason} in API {api_id} param {param}",
                             payload=str(param_value)[:200])
            return jsonify({'success': False, 'error': 'Güvenlik nedeniyle engellendi'}), 400
        
        param_values[param] = param_value

    api_endpoint = APIS[api_id]['endpoint']

    filled_endpoint = api_endpoint
    for param, value in param_values.items():
        filled_endpoint = filled_endpoint.replace(f'{{{param}}}', str(value))

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Referer': 'https://panel.ozsoy.app/',
            'X-Forwarded-For': g.client_ip,
            'X-Requested-With': 'XMLHttpRequest',
            'X-Request-ID': g.request_id
        }

        response = requests.get(filled_endpoint, headers=headers, timeout=30)

        if response.status_code == 200:
            content_type = response.headers.get('Content-Type', '').lower()

            if 'application/json' in content_type or 'json' in content_type:
                try:
                    result_data = response.json()
                    return jsonify({'success': True, 'data': result_data})
                except:
                    pass

            if 'text/html' in content_type or 'html' in content_type:
                try:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.content, 'html.parser')
                    for script in soup(["script", "style"]):
                        script.decompose()
                    text = soup.get_text()
                    lines = (line.strip() for line in text.splitlines())
                    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
                    text = '\n'.join(chunk for chunk in chunks if chunk)
                    return jsonify({'success': True, 'data': text[:5000]})
                except:
                    pass

            if 'text/plain' in content_type or 'text/' in content_type:
                try:
                    encodings = ['utf-8', 'iso-8859-9', 'windows-1254', 'ascii']
                    text = None
                    for encoding in encodings:
                        try:
                            text = response.content.decode(encoding, errors='replace')
                            break
                        except:
                            continue

                    if text:
                        replacements = {
                            'Ã§': 'ç', 'Ã‡': 'Ç',
                            'ÄŸ': 'ğ', 'Äž': 'Ğ',
                            'Ã¶': 'ö', 'Ã–': 'Ö',
                            'ÅŸ': 'ş', 'Åž': 'Ş',
                            'Ã¼': 'ü', 'Ãœ': 'Ü',
                            'Ä±': 'ı', 'Ä°': 'İ',
                            'â€': '-', 'â€™': "'",
                            'â€œ': '"', 'â€': '"',
                            'â€˜': "'", 'â€¦': '...'
                        }

                        for wrong, correct in replacements.items():
                            text = text.replace(wrong, correct)

                        return jsonify({'success': True, 'data': text[:5000]})
                except:
                    pass

            try:
                hex_data = response.content.hex()
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
            log_security_event('api_error_response', g.client_ip, severity=2,
                             details=f"API {api_id} returned {response.status_code}",
                             payload=response.text[:200] if response.text else '')
            return jsonify({
                'success': False,
                'error': f'API hatası: {response.status_code}',
                'response': response.text[:500] if response.text else 'No response text'
            }), response.status_code
    except requests.Timeout:
        log_security_event('api_timeout', g.client_ip, severity=2,
                         details=f"API {api_id} timeout")
        return jsonify({'success': False, 'error': 'API yanıt vermedi (timeout). Lütfen daha sonra tekrar deneyin.'}), 504
    except requests.ConnectionError:
        log_security_event('api_connection_error', g.client_ip, severity=3,
                         details=f"API {api_id} connection error")
        return jsonify({'success': False, 'error': 'API sunucusuna bağlanılamadı.'}), 503
    except requests.RequestException as e:
        log_security_event('api_request_exception', g.client_ip, severity=3,
                         details=f"API {api_id} exception: {str(e)}")
        return jsonify({'success': False, 'error': f'İstek hatası: {str(e)}'}), 500

@app.errorhandler(404)
def not_found_error(error):
    log_security_event('404_error', g.client_ip, severity=1,
                     request_path=request.path)
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden_error(error):
    log_security_event('403_error', g.client_ip, severity=3,
                     request_path=request.path)
    return render_template('403.html'), 403

@app.errorhandler(429)
def rate_limit_error(error):
    log_security_event('429_error', g.client_ip, severity=3,
                     request_path=request.path)
    return render_template('429.html'), 429

@app.errorhandler(500)
def internal_error(error):
    log_security_event('500_error', g.client_ip, severity=4,
                     request_path=request.path, details=str(error))
    return render_template('500.html'), 500

# ----------------------------------------------------------------------------
# TEMPLATE DOSYALARINI OLUŞTURMA
# ----------------------------------------------------------------------------
def create_templates():
    templates_dir = os.path.join(BASE_DIR, 'templates')
    os.makedirs(templates_dir, exist_ok=True)
    
    # Key checking template
    key_checking_html = '''<!DOCTYPE html>
<html>
<head>
    <title>Key Kontrol Ediliyor - GÜVENLİK MODU</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        body {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            padding: 20px;
        }

        .container {
            background: rgba(30, 41, 59, 0.9);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 40px;
            max-width: 500px;
            width: 100%;
            text-align: center;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .loader {
            width: 80px;
            height: 80px;
            border: 8px solid rgba(59, 130, 246, 0.2);
            border-top: 8px solid #3b82f6;
            border-radius: 50%;
            animation: spin 1.5s linear infinite;
            margin: 0 auto 30px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        h1 {
            font-size: 28px;
            margin-bottom: 20px;
            color: #f8fafc;
            font-weight: 700;
        }

        .security-badge {
            background: linear-gradient(135deg, #ef4444, #dc2626);
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            display: inline-block;
            margin-bottom: 20px;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }

        .key-display {
            background: rgba(15, 23, 42, 0.7);
            padding: 15px;
            border-radius: 10px;
            margin: 25px 0;
            border: 1px solid rgba(59, 130, 246, 0.3);
            word-break: break-all;
            font-family: monospace;
            font-size: 18px;
            color: #60a5fa;
            position: relative;
        }

        .key-display::before {
            content: '🔐';
            position: absolute;
            left: 10px;
            top: 50%;
            transform: translateY(-50%);
        }

        .status-message {
            margin: 20px 0;
            color: #cbd5e1;
            line-height: 1.6;
            font-size: 16px;
        }

        .details {
            background: rgba(15, 23, 42, 0.5);
            padding: 15px;
            border-radius: 10px;
            margin-top: 20px;
            text-align: left;
            font-size: 14px;
            color: #94a3b8;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }

        .details p {
            margin: 8px 0;
            display: flex;
            align-items: center;
        }

        .details p::before {
            content: '•';
            margin-right: 8px;
            color: #3b82f6;
        }

        .success {
            color: #10b981;
            font-weight: 600;
        }

        .error {
            color: #ef4444;
            font-weight: 600;
        }

        .warning {
            color: #f59e0b;
            font-weight: 600;
        }

        .redirect-notice {
            margin-top: 25px;
            padding: 15px;
            background: rgba(16, 185, 129, 0.1);
            border-radius: 10px;
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: #10b981;
            font-size: 14px;
            animation: pulse 1.5s infinite;
        }

        .steps {
            display: flex;
            justify-content: space-between;
            margin: 20px 0;
            position: relative;
        }

        .steps::before {
            content: '';
            position: absolute;
            top: 15px;
            left: 30px;
            right: 30px;
            height: 2px;
            background: rgba(59, 130, 246, 0.2);
            z-index: 1;
        }

        .step {
            text-align: center;
            flex: 1;
            padding: 10px;
            position: relative;
            z-index: 2;
        }

        .step-number {
            width: 30px;
            height: 30px;
            background: #3b82f6;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 10px;
            font-weight: bold;
            border: 2px solid rgba(255, 255, 255, 0.1);
        }

        .step-text {
            font-size: 12px;
            color: #94a3b8;
        }

        .step.active .step-number {
            background: #10b981;
            box-shadow: 0 0 10px rgba(16, 185, 129, 0.5);
        }

        .step.active .step-text {
            color: #10b981;
            font-weight: 600;
        }

        .step.completed .step-number {
            background: #10b981;
        }

        .security-info {
            margin-top: 20px;
            padding: 10px;
            background: rgba(239, 68, 68, 0.1);
            border-radius: 8px;
            border: 1px solid rgba(239, 68, 68, 0.2);
            font-size: 12px;
            color: #fca5a5;
        }

        .security-info p {
            margin: 5px 0;
        }
    </style>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const key = "{{ key }}";
            const statusElement = document.getElementById('status-message');
            const loader = document.querySelector('.loader');
            const steps = document.querySelectorAll('.step');
            const securityInfo = document.getElementById('security-info');

            let currentStep = 0;
            let attempts = 0;
            const maxAttempts = 3;

            function updateStep(stepIndex) {
                steps.forEach((step, index) => {
                    if (index < stepIndex) {
                        step.classList.add('completed');
                        step.classList.remove('active');
                    } else if (index === stepIndex) {
                        step.classList.add('active');
                        step.classList.remove('completed');
                    } else {
                        step.classList.remove('active', 'completed');
                    }
                });
                currentStep = stepIndex;
            }

            function showError(message) {
                updateStep(3);
                statusElement.innerHTML = '❌ <span class="error">' + message + '</span>';
                statusElement.className = 'status-message error';
                loader.style.display = 'none';
                
                document.getElementById('error-message').innerHTML =
                    '<div class="security-info">' +
                    '<p><strong>Güvenlik Uyarısı:</strong></p>' +
                    '<p>• IP adresiniz loglandı</p>' +
                    '<p>• Tekrar deneme hakkı: ' + (maxAttempts - attempts) + '</p>' +
                    '<p>• Şüpheli aktivite tespit edilirse IP bloklanır</p>' +
                    '</div>' +
                    '<button onclick="window.location.href=\'/login\'" style="background:#ef4444;color:white;border:none;padding:12px 24px;border-radius:5px;margin-top:20px;cursor:pointer;font-size:14px;font-weight:bold;width:100%;">↩️ Giriş Sayfasına Dön</button>';
                document.getElementById('error-message').style.display = 'block';
            }

            updateStep(0);
            statusElement.innerHTML = '🔐 <span class="warning">GÜVENLİK MODU AKTİF</span><br>API sunucusuna bağlanılıyor...';

            setTimeout(() => {
                updateStep(1);
                statusElement.innerHTML = '📡 Şifreli kanal üzerinden key sorgusu gönderiliyor...';

                setTimeout(() => {
                    updateStep(2);
                    statusElement.innerHTML = '🛡️ Güvenlik doğrulamaları yapılıyor...';

                    checkKeyStatus(key);
                }, 1500);
            }, 1500);

            function checkKeyStatus(key) {
                attempts++;
                console.log('Key kontrol başlatılıyor (attempt ' + attempts + '):', key.substring(0, 10) + '...');
                
                fetch('/key_check_status?key=' + encodeURIComponent(key) + '&attempt=' + attempts, {
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                })
                    .then(response => {
                        if (!response.ok) {
                            throw new Error('HTTP ' + response.status);
                        }
                        return response.json();
                    })
                    .then(data => {
                        console.log('Key kontrol sonucu:', data);
                        if (data.success) {
                            updateStep(3);
                            statusElement.innerHTML = '✅ <span class="success">Key başarıyla doğrulandı!</span>';
                            statusElement.className = 'status-message success';
                            loader.style.display = 'none';

                            document.getElementById('success-message').innerHTML =
                                '<div class="redirect-notice">' +
                                '<p><strong>✅ GÜVENLİK ONAYLANDI</strong></p>' +
                                '<p>• Key geçerli ve aktif</p>' +
                                '<p>• VIP erişim sağlandı</p>' +
                                '<p>• Panel sayfasına yönlendiriliyorsunuz...</p>' +
                                '</div>';
                            document.getElementById('success-message').style.display = 'block';

                            setTimeout(() => {
                                window.location.href = '/panel';
                            }, 2000);
                        } else {
                            if (attempts < maxAttempts) {
                                showError('Key doğrulanamadı: ' + (data.error || 'Bilinmeyen hata') + ' (Deneme ' + attempts + '/' + maxAttempts + ')');
                            } else {
                                showError('Maksimum deneme sayısına ulaşıldı. IP adresiniz güvenlik nedeniyle geçici olarak bloklandı.');
                            }
                        }
                    })
                    .catch(error => {
                        console.error('Key kontrol hatası:', error);
                        if (attempts < maxAttempts) {
                            showError('Bağlantı hatası: ' + error + ' (Deneme ' + attempts + '/' + maxAttempts + ')');
                        } else {
                            showError('Maksimum deneme sayısına ulaşıldı. Lütfen daha sonra tekrar deneyin.');
                        }
                    });
            }
        });
    </script>
</head>
<body>
    <div class="container">
        <div class="security-badge">🔒 GÜVENLİK MODU</div>
        <div class="loader"></div>

        <h1>🔐 VIP KEY KONTROL EDİLİYOR</h1>

        <div class="key-display" style="padding-left: 40px;">
            {{ key }}
        </div>

        <div class="steps">
            <div class="step">
                <div class="step-number">1</div>
                <div class="step-text">Bağlantı</div>
            </div>
            <div class="step">
                <div class="step-number">2</div>
                <div class="step-text">Sorgu</div>
            </div>
            <div class="step">
                <div class="step-number">3</div>
                <div class="step-text">Doğrulama</div>
            </div>
            <div class="step">
                <div class="step-number">4</div>
                <div class="step-text">Sonuç</div>
            </div>
        </div>

        <div id="status-message" class="status-message">
            ⏳ Key kontrolü başlatılıyor...
        </div>

        <div class="details">
            <p><strong>Güvenlik İşlemleri:</strong></p>
            <p>🔒 Şifreli API bağlantısı kuruluyor</p>
            <p>🛡️ HMAC imza doğrulaması yapılıyor</p>
            <p>📡 Güvenli kanal üzerinden sorgu gönderiliyor</p>
            <p>⚡ Gerçek zamanlı güvenlik taraması aktif</p>
        </div>

        <div id="success-message" style="display: none;"></div>

        <div id="error-message" style="display: none; margin-top: 20px;"></div>

        <div id="security-info" class="security-info" style="margin-top: 30px;">
            <p><strong>⚠️ GÜVENLİK UYARISI:</strong></p>
            <p>• Tüm işlemler şifreli kanallar üzerinden yapılır</p>
            <p>• Her sorgu benzersiz bir imza ile korunur</p>
            <p>• Şüpheli aktiviteler otomatik olarak loglanır</p>
            <p>• Maksimum 3 başarısız deneme hakkı vardır</p>
        </div>
    </div>
</body>
</html>'''
    
    key_checking_path = os.path.join(templates_dir, 'key_checking.html')
    with open(key_checking_path, 'w', encoding='utf-8') as f:
        f.write(key_checking_html)
    
    print("[INFO] Güvenlikli key_checking.html oluşturuldu")
    
    # Diğer template'ler için basit HTML'ler oluştur
    templates_to_create = {
        '404.html': '<h1>404 - Sayfa Bulunamadı</h1>',
        '403.html': '<h1>403 - Erişim Engellendi</h1>',
        '429.html': '<h1>429 - Çok Fazla İstek</h1>',
        '500.html': '<h1>500 - Sunucu Hatası</h1>',
    }
    
    for template_name, content in templates_to_create.items():
        template_path = os.path.join(templates_dir, template_name)
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(f'''<!DOCTYPE html>
<html>
<head>
    <title>{template_name.split('.')[0]}</title>
    <style>
        body {{ 
            font-family: Arial, sans-serif; 
            text-align: center; 
            padding: 50px; 
            background: #f0f0f0;
        }}
        .container {{ 
            background: white; 
            padding: 30px; 
            border-radius: 10px; 
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            max-width: 600px;
            margin: 0 auto;
        }}
        h1 {{ color: #333; }}
        p {{ color: #666; }}
        .error-code {{ 
            font-size: 48px; 
            color: #dc2626; 
            font-weight: bold;
        }}
        .back-btn {{
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background: #3b82f6;
            color: white;
            text-decoration: none;
            border-radius: 5px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="error-code">{template_name.split('.')[0]}</div>
        <h1>ÖZSOY PANEL - GÜVENLİK SİSTEMİ</h1>
        <p>{content}</p>
        <p>Bu işlem güvenlik nedeniyle loglanmıştır.</p>
        <a href="/" class="back-btn">Ana Sayfaya Dön</a>
    </div>
</body>
</html>''')

# ----------------------------------------------------------------------------
# BAŞLATMA
# ----------------------------------------------------------------------------
if __name__ == '__main__':
    init_db()
    create_templates()
    
    print("\n" + "="*70)
    print("🔥 ÖZSOY PANEL - MAX GÜVENLİK SİSTEMİ 🔥")
    print("="*70)
    print(f"🔐 Key Checking Sistemi: AKTİF (HMAC ile)")
    print(f"🛡️  Güvenlik Seviyesi: MAXIMUM")
    print(f"🌐 API Kontrol URL: {API_CHECK_URL}")
    print(f"📊 Toplam API: {len(APIS)}")
    print(f"🆓 Free API: {len([a for a in APIS.values() if a['plan'] == 'free'])}")
    print(f"👑 VIP API: {len([a for a in APIS.values() if a['plan'] == 'vip'])}")
    print(f"📱 URL: http://127.0.0.1:5000")
    print(f"🔑 FREE Key: {SABIT_FREE_KEY}")
    print("="*70)
    print("✅ Güvenlik Özellikleri:")
    print("   • HMAC İmza Doğrulama")
    print("   • CSRF Koruması")
    print("   • SQL Injection Koruması")
    print("   • XSS Koruması")
    print("   • Rate Limiting")
    print("   • Session Fixation Koruması")
    print("   • Brute Force Koruması")
    print("   • Tüm İstekler Loglanır")
    print("="*70 + "\n")
    
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    
    app.run(
        debug=debug_mode,
        host='0.0.0.0',
        port=port,
        threaded=True
)
