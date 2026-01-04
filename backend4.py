"""
ÖZSOY PANEL - TAM SİSTEM
- Robot doğrulama
- VIP/Free key sistemi
- 60+ API
- Güvenlik max
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
from collections import defaultdict, deque
import asyncio

from flask import Flask, request, session, jsonify, render_template, redirect, url_for, flash, g, abort
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
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=6)

# Session ayarları
app.config.update(
    SESSION_TYPE='filesystem',
    SESSION_FILE_DIR=os.path.join(BASE_DIR, 'flask_session'),
    SESSION_PERMANENT=False,
    SESSION_USE_SIGNER=True,
    SESSION_COOKIE_SECURE=False,  # Local için False
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# Session klasörünü oluştur
os.makedirs(os.path.join(BASE_DIR, 'flask_session'), exist_ok=True)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

db = SQLAlchemy(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["2000 per day", "500 per hour"],
    storage_uri="memory://"
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

    def is_expired(self):
        if not self.expires_at:
            return False
        return datetime.now() > self.expires_at

    def is_vip(self):
        return self.plan != 'free'

# ----------------------------------------------------------------------------
# TÜM API'LER
# ----------------------------------------------------------------------------
APIS = {
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
    'papara': {
        'name': 'Papara Numarası Sorgu',
        'plan': 'vip',
        'endpoint': 'https://paparadata.onrender.com/f3system/api/papara?paparano={paparano}',
        'params': ['paparano']
    },
    'adeczane': {
        'name': 'Ad Eczane Sorgu',
        'plan': 'vip',
        'endpoint': 'https://eczanedataf3.onrender.com/f3system/api/eczane?ad={ad}',
        'params': ['ad']
    },
    'tcserino': {
        'name': 'TC Seri No Sorgu',
        'plan': 'vip',
        'endpoint': 'https://serinodataf3.onrender.com/serino?tc={tc}',
        'params': ['tc']
    },
    'advergi': {
        'name': 'Ad Vergi Sorgu',
        'plan': 'vip',
        'endpoint': 'https://vergidata-hv43.onrender.com/f3system/api/vergi?isim={isim}',
        'params': ['isim']
    },
    'phishing_create': {
        'name': 'Phishing Link Oluşturma',
        'plan': 'vip',
        'endpoint': 'https://phishing-n3gi.onrender.com/create_link?token={token}&id={id}&template={template}',
        'params': ['token', 'id', 'template']
    },
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
    'vergi_borc': {
        'name': 'Vergi Borç Sorgu',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/vergi/borc-sorgu?tc={tc}',
        'params': ['tc']
    },
    'askerlik_durum': {
        'name': 'Askerlik Durumu',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/askerlik/durum?tc={tc}',
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
                owner='SYSTEM'
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
                owner='SYSTEM'
            )
            db.session.add(key)
            db.session.commit()
        return key
    key = Key.query.filter_by(key=kstr).first()
    if not key or not key.active or key.is_expired():
        return None
    return key

def check_key_via_api(kstr):
    if not kstr or len(kstr) != 20:
        return {'success': False, 'error': 'Geçersiz key formatı'}
    try:
        url = f"{API_CHECK_URL}?key={kstr}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            try:
                data = response.json()
                if data.get('durum') == 'aktif':
                    return {
                        'success': True,
                        'key': kstr,
                        'status': 'active',
                        'expires_at': data.get('bitis')
                    }
                else:
                    return {'success': False, 'error': 'Key pasif'}
            except:
                text = response.text.lower()
                if 'aktif' in text or 'true' in text:
                    return {'success': True, 'key': kstr, 'status': 'active'}
                else:
                    return {'success': False, 'error': 'Key bulunamadı'}
        else:
            return {'success': False, 'error': f'API hatası: {response.status_code}'}
    except Exception as e:
        return {'success': False, 'error': f'Kontrol hatası: {str(e)}'}

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        ip = request.remote_addr
    try:
        ipaddress.ip_address(ip)
        return ip
    except:
        return '0.0.0.0'

# ----------------------------------------------------------------------------
# DECORATOR'LAR
# ----------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'key' not in session:
            flash('Lütfen giriş yapın')
            return redirect(url_for('login'))
        
        key_str = session.get('key')
        key = verify_key_string(key_str)
        
        if not key and key_str != SABIT_FREE_KEY and len(key_str) == 20:
            # API'den kontrol et
            result = check_key_via_api(key_str)
            if result.get('success'):
                # Key'i veritabanına kaydet
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
                    key = Key(
                        key=key_str,
                        plan='vip',
                        created_at=datetime.now(),
                        expires_at=expires_at,
                        active=True,
                        notes='API üzerinden doğrulandı',
                        owner='VIP User',
                        api_created=True,
                        api_key_id=f"api_{key_str[:10]}"
                    )
                    db.session.add(key)
                    db.session.commit()
                
                # Session'ı güncelle
                session['key'] = key.key
                session['plan'] = key.plan
                session['key_id'] = key.id
                session['logged_in'] = True
                session['username'] = f"user{key.id}"
                session['is_vip'] = key.plan != 'free'
                session['login_ip'] = get_client_ip()
                session.modified = True
                
                # Key kullanımını güncelle
                key.last_used = datetime.now()
                key.usage_count += 1
                key.last_ip = get_client_ip()
                db.session.commit()
                
                return f(*args, **kwargs)
            else:
                session.clear()
                flash(f'Key geçersiz: {result.get("error", "Bilinmeyen hata")}')
                return redirect(url_for('login'))
        
        if not key:
            session.clear()
            flash('Key geçersiz veya süresi dolmuş')
            return redirect(url_for('login'))
        
        # Key kullanımını güncelle
        key.last_used = datetime.now()
        key.usage_count += 1
        key.last_ip = get_client_ip()
        db.session.commit()
        
        return f(*args, **kwargs)
    return decorated_function

# ----------------------------------------------------------------------------
# ROUTE'LAR
# ----------------------------------------------------------------------------
@app.before_request
def before_request():
    g.client_ip = get_client_ip()

@app.route('/')
def index():
    return redirect(url_for('robot_dogrulama'))

@app.route('/robot_dogrulama')
@limiter.limit("10 per minute")
def robot_dogrulama():
    next_page = request.args.get('next', '/login')
    session['csrf_token'] = secrets.token_urlsafe(32)
    session['next_page'] = next_page  # Hedef sayfayı sakla
    session.modified = True
    return render_template('robot_dogrulama.html', next_page=next_page, csrf_token=session['csrf_token'])

@app.route('/keneviz_challenge', methods=['POST'])
@limiter.limit("5 per minute")
def keneviz_challenge():
    csrf_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
    if not csrf_token or not hmac.compare_digest(csrf_token, session.get('csrf_token', '')):
        return jsonify({'success': False, 'error': 'CSRF token gerekli'}), 403
    
    nonce = secrets.token_urlsafe(16)
    session['keneviz_challenge'] = {
        'nonce': nonce,
        'ts': int(time.time()),
        'ip': g.client_ip
    }
    session.modified = True
    return jsonify({'challenge_id': nonce, 'ts': session['keneviz_challenge']['ts']})

@app.route('/keneviz_verify', methods=['POST'])
@limiter.limit("5 per minute")
def keneviz_verify():
    try:
        data = request.get_json() or {}
        saved = session.get('keneviz_challenge')
        if not saved:
            return jsonify({'success': False, 'error': 'no_challenge'}), 400
        
        if saved.get('ip') != g.client_ip:
            return jsonify({'success': False, 'error': 'ip_mismatch'}), 400
        
        incoming_nonce = data.get('challenge_id')
        if not incoming_nonce or incoming_nonce != saved.get('nonce'):
            return jsonify({'success': False, 'error': 'challenge_mismatch'}), 400
        
        if time.time() - saved.get('ts', 0) > 300:
            return jsonify({'success': False, 'error': 'timeout'}), 400
        
        # Doğrulama başarılı
        session['keneviz_verified'] = True
        session['verified_at'] = datetime.now().isoformat()
        session.pop('keneviz_challenge', None)
        session.modified = True
        
        next_page = session.get('next_page', '/login')
        return jsonify({
            'success': True,
            'message': 'Doğrulama başarılı',
            'redirect': next_page
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", methods=['POST'])
def login():
    # GET isteği için
    if request.method == 'GET':
        # Eğer robot doğrulaması yapılmamışsa
        if not session.get('keneviz_verified'):
            flash('Önce robot doğrulaması yapmalısınız!')
            return redirect(url_for('robot_dogrulama') + '?next=/login')
        
        # Doğrulama süresi kontrolü (30 dakika)
        verified_at = session.get('verified_at')
        if verified_at:
            try:
                verified_time = datetime.fromisoformat(verified_at)
                if (datetime.now() - verified_time).total_seconds() > 1800:  # 30 dakika
                    session.pop('keneviz_verified', None)
                    session.pop('verified_at', None)
                    flash('Doğrulama süresi doldu, tekrar yapın!')
                    return redirect(url_for('robot_dogrulama') + '?next=/login')
            except:
                pass
        
        session['csrf_token'] = secrets.token_urlsafe(32)
        session.modified = True
        return render_template('login.html', csrf_token=session['csrf_token'])
    
    # POST isteği için
    csrf_token = request.form.get('csrf_token')
    if not csrf_token or not hmac.compare_digest(csrf_token, session.get('csrf_token', '')):
        flash('Güvenlik hatası! Lütfen tekrar deneyin.')
        return redirect(url_for('login'))
    
    # Robot doğrulama kontrolü
    if not session.get('keneviz_verified'):
        flash('Önce robot doğrulaması yapmalısınız!')
        return redirect(url_for('robot_dogrulama') + '?next=/login')
    
    # Doğrulama süresi kontrolü
    verified_at = session.get('verified_at')
    if verified_at:
        try:
            verified_time = datetime.fromisoformat(verified_at)
            if (datetime.now() - verified_time).total_seconds() > 1800:  # 30 dakika
                session.pop('keneviz_verified', None)
                session.pop('verified_at', None)
                flash('Doğrulama süresi doldu, tekrar yapın!')
                return redirect(url_for('robot_dogrulama') + '?next=/login')
        except:
            pass
    
    key_str = request.form.get('key', '').strip().upper()
    if not key_str:
        flash('Key giriniz!')
        return redirect(url_for('login'))
    
    # FREE key kontrolü
    if key_str == SABIT_FREE_KEY:
        key = verify_key_string(key_str)
        if not key:
            flash('Free key geçersiz!')
            return redirect(url_for('login'))
        
        # Session'ı ayarla
        session['key'] = key.key
        session['plan'] = key.plan
        session['key_id'] = key.id
        session['logged_in'] = True
        session['username'] = f"user{key.id}"
        session['is_vip'] = False
        session['login_ip'] = g.client_ip
        session.pop('keneviz_verified', None)
        session.pop('verified_at', None)
        session.pop('csrf_token', None)
        session.modified = True
        
        # Key kullanımını güncelle
        key.last_used = datetime.now()
        key.usage_count += 1
        key.last_ip = g.client_ip
        db.session.commit()
        
        return redirect(url_for('panel'))
    
    # 20 haneli değilse hata ver
    if len(key_str) != 20:
        flash('Geçersiz key formatı! 20 haneli VIP key veya FREE key girin.')
        return redirect(url_for('login'))
    
    # Önce lokal veritabanında kontrol et
    key = verify_key_string(key_str)
    if key and key.active and not key.is_expired():
        # Session'ı ayarla
        session['key'] = key.key
        session['plan'] = key.plan
        session['key_id'] = key.id
        session['logged_in'] = True
        session['username'] = f"user{key.id}"
        session['is_vip'] = key.plan != 'free'
        session['login_ip'] = g.client_ip
        session.pop('keneviz_verified', None)
        session.pop('verified_at', None)
        session.pop('csrf_token', None)
        session.modified = True
        
        # Key kullanımını güncelle
        key.last_used = datetime.now()
        key.usage_count += 1
        key.last_ip = g.client_ip
        db.session.commit()
        
        return redirect(url_for('panel'))
    
    # Key bulunamadı, API'den kontrol et
    return render_template('key_checking.html', key=key_str)

@app.route('/key_check_status')
@limiter.limit("5 per minute")
def key_check_status():
    key_str = request.args.get('key', '').upper().strip()
    if not key_str or len(key_str) != 20:
        return jsonify({'success': False, 'error': 'Geçersiz key formatı'})
    
    try:
        result = check_key_via_api(key_str)
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
                key = Key(
                    key=key_str,
                    plan='vip',
                    created_at=datetime.now(),
                    expires_at=expires_at,
                    active=True,
                    notes='API üzerinden doğrulandı',
                    owner='VIP User',
                    api_created=True,
                    api_key_id=f"api_{key_str[:10]}"
                )
                db.session.add(key)
                db.session.commit()
            
            # Session'ı ayarla
            session['key'] = key.key
            session['plan'] = key.plan
            session['key_id'] = key.id
            session['logged_in'] = True
            session['username'] = f"user{key.id}"
            session['is_vip'] = True
            session['login_ip'] = g.client_ip
            session.pop('keneviz_verified', None)
            session.pop('verified_at', None)
            session.modified = True
            
            # Key kullanımını güncelle
            key.last_used = datetime.now()
            key.usage_count += 1
            key.last_ip = g.client_ip
            db.session.commit()
            
            return jsonify({
                'success': True,
                'key': key_str,
                'plan': 'vip',
                'is_vip': True,
                'message': 'Key başarıyla doğrulandı!',
                'redirect': '/panel'
            })
        else:
            return jsonify({'success': False, 'error': result.get('error', 'Key doğrulanamadı')})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/panel')
@login_required
@limiter.limit("30 per minute")
def panel():
    key_str = session.get('key')
    key = verify_key_string(key_str)
    
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
    
    from datetime import date
    today = date.today()
    today_calls = key.usage_count if key.last_used and key.last_used.date() == today else 0
    
    total_apis = len(APIS)
    free_apis = len([a for a in APIS.values() if a['plan'] == 'free'])
    vip_apis = len([a for a in APIS.values() if a['plan'] == 'vip'])
    user_apis = total_apis if key.is_vip() else free_apis
    
    return render_template('panel.html',
        key=key,
        username=session.get('username', 'Misafir'),
        plan='VIP' if key.is_vip() else 'FREE',
        is_vip=key.is_vip(),
        remaining=remaining,
        today_calls=today_calls,
        total_apis=total_apis,
        free_apis=free_apis,
        vip_apis=vip_apis,
        user_apis=user_apis,
        user_ip=session.get('login_ip', 'Bilinmiyor'),
        last_login=key.last_used,
        free_key=SABIT_FREE_KEY
    )

@app.route('/sorgu.html')
@login_required
@limiter.limit("20 per minute")
def sorgu_page():
    api_id = request.args.get('api', '').lower()
    if not api_id or api_id not in APIS:
        flash('Geçersiz API!')
        return redirect(url_for('panel'))
    
    key_str = session.get('key')
    key = verify_key_string(key_str)
    if not key:
        session.clear()
        flash('Key geçersiz')
        return redirect(url_for('login'))
    
    api_info = APIS[api_id]
    if api_info['plan'] == 'vip' and not key.is_vip():
        flash(f"Bu API için VIP üyelik gereklidir: {api_info['name']}")
        return redirect(url_for('abonelik_page'))
    
    return render_template('sorgu.html',
                         api_id=api_id,
                         api_info=api_info,
                         is_vip=key.is_vip(),
                         username=session.get('username', 'Misafir'))

@app.route('/abonelik.html')
def abonelik_page():
    return render_template('abonelik.html')

@app.route('/api/user')
def api_user():
    if 'key' not in session:
        return jsonify({'logged_in': False, 'role': 'guest'})
    
    key_str = session.get('key')
    key = verify_key_string(key_str)
    if not key:
        session.clear()
        return jsonify({'logged_in': False, 'role': 'guest'})
    
    return jsonify({
        'logged_in': True,
        'role': 'vip' if key.plan != 'free' else 'free',
        'plan': key.plan,
        'is_vip': key.plan != 'free',
        'username': session.get('username', f"user{key.id}")
    })

@app.route('/api/list')
@login_required
@limiter.limit("10 per minute")
def api_list():
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
def api_sorgu():
    data = request.get_json() or {}
    api_id = data.get('api', '').lower()
    
    if not api_id or api_id not in APIS:
        return jsonify({'success': False, 'error': 'Geçersiz API'}), 404
    
    key_str = session.get('key')
    key = verify_key_string(key_str)
    if not key:
        session.clear()
        return jsonify({'success': False, 'error': 'Key geçersiz'}), 401
    
    if APIS[api_id]['plan'] == 'vip' and not key.is_vip():
        return jsonify({
            'success': False,
            'error': 'Bu API için VIP üyelik gereklidir',
            'redirect': '/abonelik.html'
        }), 403
    
    api_params = APIS[api_id]['params']
    for param in api_params:
        if not data.get(param):
            return jsonify({'success': False, 'error': f'{param} parametresi gereklidir'}), 400
    
    api_endpoint = APIS[api_id]['endpoint']
    filled_endpoint = api_endpoint
    for param in api_params:
        filled_endpoint = filled_endpoint.replace(f'{{{param}}}', str(data.get(param, '')))
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'X-Forwarded-For': g.client_ip
        }
        response = requests.get(filled_endpoint, headers=headers, timeout=30)
        
        if response.status_code == 200:
            try:
                result_data = response.json()
                return jsonify({'success': True, 'data': result_data})
            except:
                return jsonify({'success': True, 'data': response.text[:5000]})
        else:
            return jsonify({
                'success': False,
                'error': f'API hatası: {response.status_code}',
                'response': response.text[:500] if response.text else ''
            }), response.status_code
    except requests.Timeout:
        return jsonify({'success': False, 'error': 'API yanıt vermedi (timeout)'}), 504
    except Exception as e:
        return jsonify({'success': False, 'error': f'İstek hatası: {str(e)}'}), 500

# ----------------------------------------------------------------------------
# ERROR HANDLERS
# ----------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403

@app.errorhandler(429)
def ratelimit_error(error):
    return render_template('429.html'), 429

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

# ----------------------------------------------------------------------------
# TEMPLATE DOSYALARINI OLUŞTURMA
# ----------------------------------------------------------------------------
def create_templates():
    templates_dir = os.path.join(BASE_DIR, 'templates')
    os.makedirs(templates_dir, exist_ok=True)
    
    # robot_dogrulama.html
    robot_html = '''<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Güvenlik Doğrulaması - sorgupaneli.2026tr.xyz</title>
    <meta name="csrf-token" content="{{ csrf_token }}">
    <style>
        body {
            background-color: #222222;
            color: #ffffff;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            box-sizing: border-box;
        }

        .wrapper {
            width: 100%;
            max-width: 450px;
            animation: fadeIn 0.8s ease-in;
        }

        h1 { 
            font-size: 24px; 
            margin-bottom: 10px; 
            font-weight: 500; 
        }
        
        .sub-text { 
            font-size: 16px; 
            margin-bottom: 25px; 
            color: #eee; 
            line-height: 1.4; 
        }

        .verify-container {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid #444;
            padding: 15px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            cursor: pointer;
            user-select: none;
            transition: all 0.2s;
            border-radius: 4px;
        }

        .verify-container:hover { 
            background: rgba(255, 255, 255, 0.05); 
            border-color: #666; 
        }

        .verify-container:active {
            background: rgba(255, 255, 255, 0.08);
            transform: scale(0.99);
        }

        .left-side { 
            display: flex; 
            align-items: center; 
            gap: 12px; 
        }

        .check-box {
            width: 26px;
            height: 26px;
            border: 2px solid #555;
            border-radius: 3px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #333;
            flex-shrink: 0;
        }

        .spinner {
            display: none;
            position: relative;
            width: 20px;
            height: 20px;
        }
        
        .dot {
            position: absolute;
            width: 3.5px;
            height: 3.5px;
            background: #2ecc71;
            border-radius: 50%;
            animation: cf-spin 1s infinite linear;
        }
        
        .dot:nth-child(1) { top: 0; left: 50%; transform: translateX(-50%); animation-delay: 0s; }
        .dot:nth-child(2) { top: 15%; right: 15%; animation-delay: 0.1s; }
        .dot:nth-child(3) { top: 50%; right: 0; transform: translateY(-50%); animation-delay: 0.2s; }
        .dot:nth-child(4) { bottom: 15%; right: 15%; animation-delay: 0.3s; }
        .dot:nth-child(5) { bottom: 0; left: 50%; transform: translateX(-50%); animation-delay: 0.4s; }
        .dot:nth-child(6) { bottom: 15%; left: 15%; animation-delay: 0.5s; }
        .dot:nth-child(7) { top: 50%; left: 0; transform: translateY(-50%); animation-delay: 0.6s; }
        .dot:nth-child(8) { top: 15%; left: 15%; animation-delay: 0.7s; }

        @keyframes cf-spin { 
            0%, 100% { opacity: 1; } 
            50% { opacity: 0.2; } 
        }

        .done-icon { 
            display: none; 
            color: #2ecc71; 
            font-size: 20px; 
            font-weight: bold; 
        }

        .status-msg { 
            font-size: 14px; 
            color: #fff; 
        }

        .right-side { 
            text-align: right; 
            min-width: 80px; 
        }
        
        .logo-text { 
            font-size: 11px; 
            font-weight: 700; 
            letter-spacing: 0.5px; 
            margin: 0; 
        }
        
        .links { 
            font-size: 9px; 
            color: #999; 
            text-decoration: underline; 
        }

        .info-footer { 
            margin-top: 25px; 
            font-size: 14px; 
            color: #aaa; 
        }

        .success-message {
            color: #2ecc71;
            font-size: 14px;
            margin-top: 10px;
            display: none;
            padding: 10px;
            background: rgba(46, 204, 113, 0.1);
            border-radius: 4px;
        }

        .error-message {
            color: #e74c3c;
            font-size: 14px;
            margin-top: 10px;
            display: none;
            padding: 10px;
            background: rgba(231, 76, 60, 0.1);
            border-radius: 4px;
        }

        @keyframes fadeIn { 
            from { opacity: 0; transform: translateY(10px); } 
            to { opacity: 1; transform: translateY(0); } 
        }

        @media (max-width: 480px) {
            h1 { font-size: 20px; }
            .sub-text { font-size: 15px; }
            .verify-container { padding: 12px 15px; }
        }
    </style>
</head>
<body>

<div class="wrapper">
    <h1>sorgupaneli.2026tr.xyz</h1>
    <p class="sub-text">İnsan olduğunuzu doğrulamak için lütfen kutucuğa dokunun.</p>

    <div class="verify-container" id="mainBox" tabindex="0">
        <div class="left-side">
            <div class="check-box" id="boxFrame">
                <div class="spinner" id="loader">
                    <div class="dot"></div><div class="dot"></div><div class="dot"></div><div class="dot"></div>
                    <div class="dot"></div><div class="dot"></div><div class="dot"></div><div class="dot"></div>
                </div>
                <div class="done-icon" id="okIcon">✓</div>
            </div>
            <span class="status-msg" id="msg">İnsan olduğunuzu doğrulayın</span>
        </div>
        
        <div class="right-side">
            <p class="logo-text">CLOUDFLARE</p>
            <span class="links">Gizlilik • Şartlar</span>
        </div>
    </div>

    <div class="success-message" id="successMessage"></div>
    <div class="error-message" id="errorMessage"></div>

    <p class="info-footer">Bağlantınızın güvenliği kontrol ediliyor.</p>
</div>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        const mainBox = document.getElementById('mainBox');
        const boxFrame = document.getElementById('boxFrame');
        const loader = document.getElementById('loader');
        const okIcon = document.getElementById('okIcon');
        const msg = document.getElementById('msg');
        const successMessage = document.getElementById('successMessage');
        const errorMessage = document.getElementById('errorMessage');
        
        const urlParams = new URLSearchParams(window.location.search);
        const nextPage = urlParams.get('next') || '/login';
        
        mainBox.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            startVerification();
        });
        
        mainBox.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                startVerification();
            }
        });
        
        async function startVerification() {
            mainBox.style.pointerEvents = "none";
            mainBox.style.cursor = "default";
            mainBox.style.opacity = "0.8";
            boxFrame.style.border = "none";
            loader.style.display = "block";
            msg.innerText = "Doğrulanıyor...";
            
            try {
                // 1. Önce challenge al
                const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
                const challengeResponse = await fetch('/keneviz_challenge', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    }
                });
                
                if (!challengeResponse.ok) {
                    throw new Error('Challenge alınamadı');
                }
                
                const challengeData = await challengeResponse.json();
                
                // 2. Doğrulama için 3 saniye bekle
                setTimeout(async () => {
                    try {
                        // 3. Doğrulama isteği gönder
                        const verifyResponse = await fetch('/keneviz_verify', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'X-CSRF-Token': csrfToken
                            },
                            body: JSON.stringify({
                                challenge_id: challengeData.challenge_id
                            })
                        });
                        
                        const verifyData = await verifyResponse.json();
                        
                        if (verifyData.success) {
                            // Başarılı
                            loader.style.display = "none";
                            okIcon.style.display = "block";
                            msg.innerText = "Doğrulandı";
                            
                            successMessage.textContent = 'Doğrulama başarılı! Yönlendiriliyorsunuz...';
                            successMessage.style.display = 'block';
                            
                            // 2 saniye sonra yönlendir
                            setTimeout(() => {
                                window.location.href = verifyData.redirect || nextPage;
                            }, 2000);
                        } else {
                            // Hata durumu
                            loader.style.display = "none";
                            boxFrame.style.border = "2px solid #e74c3c";
                            msg.innerText = "Doğrulama Başarısız";
                            
                            errorMessage.textContent = `Hata: ${verifyData.error || 'Doğrulama başarısız'}`;
                            errorMessage.style.display = 'block';
                            
                            // 3 saniye sonra tekrar deneme imkanı
                            setTimeout(() => {
                                mainBox.style.pointerEvents = "auto";
                                mainBox.style.cursor = "pointer";
                                mainBox.style.opacity = "1";
                                boxFrame.style.border = "2px solid #555";
                                msg.innerText = "İnsan olduğunuzu doğrulayın";
                                loader.style.display = "none";
                                okIcon.style.display = "none";
                                errorMessage.style.display = "none";
                            }, 3000);
                        }
                    } catch (error) {
                        loader.style.display = "none";
                        boxFrame.style.border = "2px solid #e74c3c";
                        msg.innerText = "Doğrulama Başarısız";
                        
                        errorMessage.textContent = `Bağlantı hatası: ${error.message}`;
                        errorMessage.style.display = 'block';
                        
                        // 3 saniye sonra tekrar deneme imkanı
                        setTimeout(() => {
                            mainBox.style.pointerEvents = "auto";
                            mainBox.style.cursor = "pointer";
                            mainBox.style.opacity = "1";
                            boxFrame.style.border = "2px solid #555";
                            msg.innerText = "İnsan olduğunuzu doğrulayın";
                            loader.style.display = "none";
                            okIcon.style.display = "none";
                            errorMessage.style.display = "none";
                        }, 3000);
                    }
                }, 3000);
                
            } catch (error) {
                loader.style.display = "none";
                boxFrame.style.border = "2px solid #e74c3c";
                msg.innerText = "Doğrulama Başarısız";
                
                errorMessage.textContent = `Başlangıç hatası: ${error.message}`;
                errorMessage.style.display = 'block';
                
                // 3 saniye sonra tekrar deneme imkanı
                setTimeout(() => {
                    mainBox.style.pointerEvents = "auto";
                    mainBox.style.cursor = "pointer";
                    mainBox.style.opacity = "1";
                    boxFrame.style.border = "2px solid #555";
                    msg.innerText = "İnsan olduğunuzu doğrulayın";
                    loader.style.display = "none";
                    okIcon.style.display = "none";
                    errorMessage.style.display = "none";
                }, 3000);
            }
        }
    });
</script>
</body>
</html>'''
    
    with open(os.path.join(templates_dir, 'robot_dogrulama.html'), 'w', encoding='utf-8') as f:
        f.write(robot_html)
    
    # login.html
    login_html = '''<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>ÖZSOY PANEL 2025 | VIP Giriş</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #0A0A0F;
      --bg-darker: #07070B;
      --bg-card: rgba(20, 20, 30, 0.85);
      --accent-blue: #3B82F6;
      --accent-purple: #8B5CF6;
      --accent-cyan: #06D6A0;
      --text-light: #F8FAFC;
      --text-dim: #94A3B8;
      --border-dark: rgba(255, 255, 255, 0.08);
      --gradient-primary: linear-gradient(135deg, #3B82F6 0%, #8B5CF6 50%, #06D6A0 100%);
      --gradient-card: linear-gradient(145deg, rgba(30, 30, 45, 0.95), rgba(20, 20, 30, 0.95));
      --shadow-card: 0 25px 50px rgba(0, 0, 0, 0.5);
    }

    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    html, body {
      height: 100%;
      overflow: hidden;
    }

    body {
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      background-color: var(--bg-darker);
      color: var(--text-light);
      position: relative;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }

    /* UYARI MESAJI */
    .warning-message {
      position: fixed;
      top: 20px;
      left: 50%;
      transform: translateX(-50%);
      width: 90%;
      max-width: 600px;
      background: linear-gradient(135deg, #dc2626, #b91c1c);
      color: white;
      padding: 14px 18px;
      border-radius: 10px;
      border: 3px solid #fbbf24;
      box-shadow: 0 10px 25px rgba(220, 38, 38, 0.5);
      z-index: 9999;
      font-size: 13px;
      font-weight: 600;
      text-align: center;
      line-height: 1.4;
      animation: warningPulse 2s infinite;
    }

    @keyframes warningPulse {
      0%, 100% { box-shadow: 0 10px 25px rgba(220, 38, 38, 0.5); }
      50% { box-shadow: 0 10px 30px rgba(220, 38, 38, 0.7); }
    }

    /* Flash Messages */
    .flash-message {
      padding: 16px 20px;
      background: rgba(239, 68, 68, 0.1);
      border-left: 4px solid #EF4444;
      border-radius: 12px;
      margin-bottom: 25px;
      display: flex;
      align-items: center;
      gap: 12px;
      animation: slideIn 0.3s ease;
    }

    .flash-message.success {
      background: rgba(34, 197, 94, 0.1);
      border-left: 4px solid #22c55e;
    }

    @keyframes slideIn {
      from {
        opacity: 0;
        transform: translateY(-10px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    /* Main Layout */
    .dashboard-container {
      display: flex;
      min-height: 100vh;
    }

    /* Left Sidebar */
    .sidebar {
      width: 280px;
      background: rgba(15, 15, 25, 0.9);
      backdrop-filter: blur(20px);
      border-right: 1px solid var(--border-dark);
      padding: 30px 20px;
      display: flex;
      flex-direction: column;
      position: relative;
      z-index: 10;
    }

    .logo-section {
      display: flex;
      align-items: center;
      gap: 15px;
      margin-bottom: 50px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border-dark);
    }

    .logo-icon {
      width: 50px;
      height: 50px;
      background: var(--gradient-primary);
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 24px;
      font-weight: 800;
      color: white;
      box-shadow: 0 10px 30px rgba(59, 130, 246, 0.3);
    }

    .logo-text {
      font-size: 22px;
      font-weight: 800;
      background: var(--gradient-primary);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .logo-year {
      font-size: 12px;
      color: var(--accent-cyan);
      font-weight: 600;
      margin-top: 4px;
      letter-spacing: 2px;
    }

    /* Stats Sidebar */
    .stats-section {
      margin-bottom: 40px;
    }

    .stats-title {
      font-size: 14px;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 2px;
      margin-bottom: 20px;
      font-weight: 600;
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 15px;
    }

    .stat-card {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-dark);
      border-radius: 12px;
      padding: 15px;
      transition: all 0.3s ease;
    }

    .stat-card:hover {
      border-color: var(--accent-blue);
      transform: translateY(-2px);
    }

    .stat-value {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-light);
      margin-bottom: 4px;
    }

    .stat-label {
      font-size: 11px;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 1px;
    }

    .stat-card:nth-child(1) .stat-value { color: var(--accent-blue); }
    .stat-card:nth-child(2) .stat-value { color: var(--accent-purple); }
    .stat-card:nth-child(3) .stat-value { color: var(--accent-cyan); }
    .stat-card:nth-child(4) .stat-value { color: #F59E0B; }

    /* Main Content */
    .main-content {
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 40px;
      position: relative;
    }

    /* Login Card */
    .login-card {
      width: 100%;
      max-width: 500px;
      background: var(--gradient-card);
      backdrop-filter: blur(30px);
      border-radius: 24px;
      border: 1px solid var(--border-dark);
      padding: 50px 40px;
      position: relative;
      overflow: hidden;
      box-shadow: var(--shadow-card);
    }

    /* Neon Border Effect */
    .login-card::before {
      content: '';
      position: absolute;
      inset: -1px;
      background: var(--gradient-primary);
      border-radius: 25px;
      z-index: -1;
      padding: 2px;
      -webkit-mask:
        linear-gradient(#fff 0 0) content-box,
        linear-gradient(#fff 0 0);
      -webkit-mask-composite: xor;
      mask-composite: exclude;
      opacity: 0.3;
    }

    .card-header {
      text-align: center;
      margin-bottom: 40px;
    }

    .card-icon {
      width: 70px;
      height: 70px;
      background: var(--gradient-primary);
      border-radius: 18px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 25px;
      font-size: 28px;
      box-shadow: 0 15px 40px rgba(59, 130, 246, 0.4);
    }

    .card-title {
      font-size: 32px;
      font-weight: 700;
      margin-bottom: 10px;
      background: linear-gradient(to right, var(--text-light), var(--accent-cyan));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .card-subtitle {
      color: var(--text-dim);
      font-size: 15px;
      line-height: 1.6;
      max-width: 400px;
      margin: 0 auto;
    }

    /* Input Section */
    .input-section {
      margin-bottom: 30px;
    }

    .input-label {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 14px;
      font-weight: 600;
      color: var(--accent-blue);
      margin-bottom: 15px;
      text-transform: uppercase;
      letter-spacing: 1px;
    }

    .key-input-wrapper {
      position: relative;
    }

    .key-input {
      width: 100%;
      padding: 20px;
      background: rgba(0, 0, 0, 0.3);
      border: 2px solid rgba(255, 255, 255, 0.1);
      border-radius: 14px;
      color: var(--text-light);
      font-size: 18px;
      font-family: 'Courier New', monospace;
      letter-spacing: 2px;
      outline: none;
      transition: all 0.3s ease;
    }

    .key-input:focus {
      border-color: var(--accent-blue);
      box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.15);
    }

    .key-input::placeholder {
      color: rgba(148, 163, 184, 0.5);
      font-family: 'Inter', sans-serif;
      letter-spacing: normal;
      font-size: 16px;
    }

    .key-hint {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-top: 12px;
      font-size: 13px;
      color: var(--text-dim);
    }

    /* Buttons */
    .button-section {
      display: flex;
      gap: 15px;
      margin-bottom: 25px;
    }

    .btn {
      padding: 18px 30px;
      border-radius: 14px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 12px;
      flex: 1;
      border: none;
      outline: none;
    }

    .btn-primary {
      background: var(--gradient-primary);
      color: white;
      box-shadow: 0 10px 30px rgba(59, 130, 246, 0.3);
    }

    .btn-primary:hover {
      transform: translateY(-3px);
      box-shadow: 0 15px 40px rgba(59, 130, 246, 0.4);
    }

    .btn-secondary {
      background: rgba(255, 255, 255, 0.05);
      color: var(--text-dim);
      border: 1px solid rgba(255, 255, 255, 0.1);
    }

    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.1);
      color: var(--text-light);
    }

    /* Demo Key */
    .demo-section {
      background: rgba(59, 130, 246, 0.1);
      border: 1px solid rgba(59, 130, 246, 0.2);
      border-radius: 14px;
      padding: 18px;
      margin-top: 25px;
      text-align: center;
    }

    .demo-title {
      font-size: 14px;
      font-weight: 600;
      color: var(--accent-blue);
      margin-bottom: 8px;
    }

    .demo-key {
      font-family: 'Courier New', monospace;
      font-size: 16px;
      color: var(--text-light);
      letter-spacing: 1px;
      background: rgba(0, 0, 0, 0.3);
      padding: 10px 15px;
      border-radius: 8px;
      display: inline-block;
      margin-top: 5px;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .demo-key:hover {
      background: rgba(0, 0, 0, 0.5);
    }

    /* Footer */
    .card-footer {
      text-align: center;
      margin-top: 30px;
      padding-top: 25px;
      border-top: 1px solid var(--border-dark);
      color: var(--text-dim);
      font-size: 13px;
    }

    .card-footer a {
      color: var(--accent-cyan);
      text-decoration: none;
      font-weight: 500;
    }

    .card-footer a:hover {
      text-decoration: underline;
    }

    /* Responsive */
    @media (max-width: 1024px) {
      .dashboard-container {
        flex-direction: column;
      }

      .sidebar {
        width: 100%;
        padding: 20px;
        border-right: none;
        border-bottom: 1px solid var(--border-dark);
      }

      .main-content {
        padding: 30px 20px;
      }

      .login-card {
        padding: 40px 30px;
      }
    }

    @media (max-width: 768px) {
      .warning-message {
        top: 15px;
        padding: 12px 16px;
        font-size: 12px;
      }

      .button-section {
        flex-direction: column;
      }

      .stats-grid {
        grid-template-columns: repeat(4, 1fr);
      }

      .card-title {
        font-size: 28px;
      }

      .card-icon {
        width: 60px;
        height: 60px;
        font-size: 24px;
      }
    }

    @media (max-width: 480px) {
      .warning-message {
        top: 10px;
        padding: 10px 14px;
        font-size: 11px;
      }

      .stats-grid {
        grid-template-columns: repeat(2, 1fr);
      }

      .login-card {
        padding: 30px 20px;
      }
    }
  </style>
</head>
<body>
  <!-- UYARI MESAJI -->
  <div class="warning-message">
    ⚠️ DİKKAT: TEK YETKİLİ VIP SATIŞ YAPANLAR @sukazatkinis ve @satisyetkili'DIR. DİĞERLERİ DOLANDIRICI OROSPU ÇOCUKLARIDIR!
  </div>

  <div class="dashboard-container">
    <!-- Left Sidebar -->
    <div class="sidebar">
      <div class="logo-section">
        <div class="logo-icon">Ö</div>
        <div>
          <div class="logo-text">ÖZSOY PANEL</div>
          <div class="logo-year">2025 EDITION</div>
        </div>
      </div>

      <div class="stats-section">
        <div class="stats-title">Sistem İstatistikleri</div>
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-value">48+</div>
            <div class="stat-label">API Servis</div>
          </div>
          <div class="stat-card">
            <div class="stat-value">99.8%</div>
            <div class="stat-label">Uptime</div>
          </div>
          <div class="stat-card">
            <div class="stat-value">1.2M</div>
            <div class="stat-label">Günlük Sorgu</div>
          </div>
          <div class="stat-card">
            <div class="stat-value">24K+</div>
            <div class="stat-label">Aktif Kullanıcı</div>
          </div>
        </div>
      </div>

      <div class="stats-section">
        <div class="stats-title">Key Bilgileri</div>
        <div class="stat-card" style="grid-column: 1 / -1;">
          <div class="stat-value" style="font-size: 18px; margin-bottom: 8px;">20 Haneli</div>
          <div class="stat-label" style="font-size: 12px;">VIP & Free Anahtar Formatı</div>
        </div>
      </div>
    </div>

    <!-- Main Content -->
    <div class="main-content">
      <div class="login-card">
        <!-- Flash Messages -->
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="flash-message {% if category == 'success' %}success{% endif %}">
                <i class="fas fa-exclamation-circle"></i>
                <span>{{ message }}</span>
              </div>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <div class="card-header">
          <div class="card-icon">
            <i class="fas fa-key"></i>
          </div>
          <h1 class="card-title">VIP Key Girişi</h1>
          <p class="card-subtitle">20 haneli anahtarınız ile premium sorgu panelimize erişin. Süresi dolan anahtarlar otomatik free plan'a düşer.</p>
        </div>

        <!-- Form -->
        <form method="POST" action="/login" id="keyForm">
          <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
          
          <div class="input-section">
            <div class="input-label">
              <i class="fas fa-key"></i>
              Anahtar Kodu
            </div>
            <div class="key-input-wrapper">
              <input
                type="text"
                name="key"
                id="keyInput"
                class="key-input"
                placeholder="ABCDEFGHIJKLMNOPQRST"
                maxlength="20"
                autofocus
                autocomplete="off"
                spellcheck="false"
                required
              />
            </div>
            <div class="key-hint">
              <i class="fas fa-info-circle"></i>
              <span>Anahtarınız yoksa yönetici ile iletişime geçin</span>
            </div>
          </div>

          <div class="demo-section">
            <div class="demo-title">Demo Anahtar</div>
            <div class="demo-key" id="demoKey">FREESORGUPANELI2025A</div>
          </div>

          <div class="button-section">
            <button class="btn btn-primary" type="submit" id="submitBtn">
              <i class="fas fa-lock-open"></i>
              Sisteme Giriş Yap
            </button>

            <button type="button" class="btn btn-secondary" onclick="window.location.href='/'">
              <i class="fas fa-arrow-left"></i>
              Geri Dön
            </button>
          </div>
        </form>

        <div class="card-footer">
          <p>© 2025 ÖZSOY PANEL | Premium Sorgu Sistemi</p>
          <p style="margin-top: 10px; font-size: 12px;">
            Anahtarınız yok mu? <a href=""></a> |
            <a href="#" style="margin-left: 10px;">Destek</a>
          </p>
        </div>
      </div>
    </div>
  </div>

  <script>
    document.addEventListener('DOMContentLoaded', function() {
      const keyInput = document.getElementById('keyInput');
      const demoKey = document.getElementById('demoKey');
      
      // Demo key click to copy
      demoKey.addEventListener('click', function() {
        const demoKeyText = this.textContent;
        navigator.clipboard.writeText(demoKeyText).then(() => {
          // Input alanına yapıştır
          keyInput.value = demoKeyText;
          
          // Animasyon
          const originalText = this.textContent;
          this.textContent = 'Anahtar Kopyalandı!';
          this.style.color = '#06D6A0';

          setTimeout(() => {
            this.textContent = originalText;
            this.style.color = '';
          }, 2000);
        });
      });

      // Auto focus on load
      keyInput.focus();
      keyInput.select();

      // Enter key to submit
      keyInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
          document.getElementById('submitBtn').click();
        }
      });

      // Flash mesajları kontrol et
      const flashMessage = document.querySelector('.flash-message');
      if (flashMessage) {
        // Eğer robot doğrulama hatası varsa, otomatik yönlendir
        if (flashMessage.textContent.includes('robot doğrulaması') || 
            flashMessage.textContent.includes('doğrulama süresi')) {
          setTimeout(() => {
            window.location.href = '/robot_dogrulama?next=/login';
          }, 2000);
        }
      }
    });
  </script>
</body>
</html>'''
    
    with open(os.path.join(templates_dir, 'login.html'), 'w', encoding='utf-8') as f:
        f.write(login_html)
    
    # key_checking.html
    key_checking_html = '''<!DOCTYPE html>
<html>
<head>
    <title>Key Kontrol Ediliyor</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        *{margin:0;padding:0;box-sizing:border-box;font-family:system-ui;}
        body{background:#0a0a1a;color:white;height:100vh;display:flex;align-items:center;justify-content:center;}
        .card{background:rgba(15,15,37,0.9);padding:40px;border-radius:20px;border:1px solid rgba(255,45,85,0.3);text-align:center;max-width:500px;width:90%;}
        .loader{width:80px;height:80px;border:8px solid rgba(255,45,85,0.2);border-top-color:#ff2d55;border-radius:50%;margin:20px auto;animation:spin 1s linear infinite;}
        @keyframes spin{to{transform:rotate(360deg);}}
        h1{color:#ff2d55;margin-bottom:20px;}
        .key-display{background:rgba(0,0,0,0.5);padding:15px;border-radius:10px;margin:20px 0;font-family:monospace;color:#00a8ff;}
        .status{color:#00ffa3;margin:15px 0;}
        .error{color:#ff2d55;}
        .success{color:#2ecc71;}
    </style>
    <script>
        document.addEventListener('DOMContentLoaded',function(){
            const key="{{ key }}";
            const status=document.getElementById('status');
            const loader=document.querySelector('.loader');
            status.textContent='Key kontrol ediliyor...';
            
            // API'den kontrol et
            fetch('/key_check_status?key='+encodeURIComponent(key))
                .then(r=>{
                    if(!r.ok) throw new Error('Sunucu hatası: '+r.status);
                    return r.json();
                })
                .then(data=>{
                    console.log('API Yanıtı:', data);
                    
                    if(data.success){
                        status.textContent='✅ Key doğrulandı! Panele yönlendiriliyorsunuz...';
                        status.className='status success';
                        
                        // 2 saniye sonra panele yönlendir
                        setTimeout(()=>{
                            window.location.href = '/panel';
                        },2000);
                    }else{
                        status.textContent='❌ ' + (data.error || 'Key doğrulanamadı');
                        status.className='status error';
                        loader.style.display='none';
                        
                        // 5 saniye sonra login sayfasına dön
                        setTimeout(()=>{
                            window.location.href='/login';
                        },5000);
                    }
                })
                .catch(e=>{
                    console.error('Hata:', e);
                    status.textContent='❌ Bağlantı hatası: ' + e.message;
                    status.className='status error';
                    loader.style.display='none';
                    
                    // 5 saniye sonra login sayfasına dön
                    setTimeout(()=>{
                        window.location.href='/login';
                    },5000);
                });
        });
    </script>
</head>
<body>
    <div class="card">
        <h1>🔐 KEY KONTROL</h1>
        <div class="key-display">{{ key }}</div>
        <div class="loader"></div>
        <div class="status" id="status"></div>
    </div>
</body>
</html>'''
    
    with open(os.path.join(templates_dir, 'key_checking.html'), 'w', encoding='utf-8') as f:
        f.write(key_checking_html)
    
    # Basit hata sayfaları
    for template, content in [
        ('404.html', '404 - Sayfa Bulunamadı'),
        ('403.html', '403 - Erişim Engellendi'),
        ('429.html', '429 - Çok Fazla İstek'),
        ('500.html', '500 - Sunucu Hatası')
    ]:
        with open(os.path.join(templates_dir, template), 'w', encoding='utf-8') as f:
            f.write(f'<h1>{content}</h1><p><a href="/">Ana Sayfa</a></p>')
    
    print("[INFO] Template'ler oluşturuldu")

# ----------------------------------------------------------------------------
# BAŞLATMA
# ----------------------------------------------------------------------------
if __name__ == '__main__':
    init_db()
    create_templates()
    print("\n" + "="*60)
    print("🔥 ÖZSOY PANEL - TAM SİSTEM")
    print("="*60)
    print(f"🔐 FREE Key: {SABIT_FREE_KEY}")
    print(f"🌐 URL: http://127.0.0.1:5000")
    print(f"📊 API Sayısı: {len(APIS)}")
    print(f"🆓 Free API: 2")
    print(f"👑 VIP API: {len(APIS)-2}")
    print("="*60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
