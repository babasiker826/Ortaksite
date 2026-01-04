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
    # FREE API'LER (SADECE 2 TANE)
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

    # VIP API'LER
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
            return redirect(url_for('login'))
        key_str = session.get('key')
        key = verify_key_string(key_str)
        if not key and key_str != SABIT_FREE_KEY and len(key_str) == 20:
            if request.method == 'GET' and request.endpoint == 'panel':
                return render_template('key_checking.html', key=key_str)
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
                session['key'] = key.key
                session['plan'] = key.plan
                session['key_id'] = key.id
                session['logged_in'] = True
                session['username'] = f"user{key.id}"
                session['is_vip'] = key.plan != 'free'
                session['login_ip'] = get_client_ip()
                session.modified = True
            else:
                session.clear()
                flash(f'Key geçersiz: {result.get("error", "Bilinmeyen hata")}')
                return redirect(url_for('login'))
        if not key:
            session.clear()
            flash('Key geçersiz veya süresi dolmuş')
            return redirect(url_for('login'))
        key.last_used = datetime.now()
        key.usage_count += 1
        key.last_ip = get_client_ip()
        db.session.commit()
        return f(*args, **kwargs)
    return decorated_function

# ----------------------------------------------------------------------------
# TÜM ROUTE'LAR
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
        session['keneviz_verified'] = True
        session.pop('keneviz_challenge', None)
        return jsonify({
            'success': True,
            'verification_token': 'verified',
            'redirect': data.get('next', '/login')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", methods=['POST'])
def login():
    if not session.get('keneviz_verified'):
        return redirect(url_for('robot_dogrulama') + '?next=/login')
    if request.method == 'GET':
        session['csrf_token'] = secrets.token_urlsafe(32)
        return render_template('login.html', csrf_token=session['csrf_token'])
    csrf_token = request.form.get('csrf_token')
    if not csrf_token or not hmac.compare_digest(csrf_token, session.get('csrf_token', '')):
        flash('Güvenlik hatası!')
        return redirect(url_for('login'))
    key_str = request.form.get('key', '').strip()
    if not key_str:
        flash('Key giriniz!')
        return redirect(url_for('login'))
    if key_str == SABIT_FREE_KEY:
        key = verify_key_string(key_str)
        if not key:
            flash('Free key geçersiz!')
            return redirect(url_for('login'))
        session['key'] = key.key
        session['plan'] = key.plan
        session['key_id'] = key.id
        session['logged_in'] = True
        session['username'] = f"user{key.id}"
        session['is_vip'] = False
        session['login_ip'] = g.client_ip
        session.pop('keneviz_verified', None)
        return redirect(url_for('panel'))
    if len(key_str) != 20:
        flash('Geçersiz key formatı! 20 haneli VIP key veya FREE key girin.')
        return redirect(url_for('login'))
    key = verify_key_string(key_str)
    if key and key.active and not key.is_expired():
        session['key'] = key.key
        session['plan'] = key.plan
        session['key_id'] = key.id
        session['logged_in'] = True
        session['username'] = f"user{key.id}"
        session['is_vip'] = key.plan != 'free'
        session['login_ip'] = g.client_ip
        session.pop('keneviz_verified', None)
        return redirect(url_for('panel'))
    return render_template('key_checking.html', key=key_str)

@app.route('/key_check_status')
@limiter.limit("5 per minute")
def key_check_status():
    key_str = request.args.get('key', '')
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
            session['key'] = key.key
            session['plan'] = key.plan
            session['key_id'] = key.id
            session['logged_in'] = True
            session['username'] = f"user{key.id}"
            session['is_vip'] = True
            session['login_ip'] = get_client_ip()
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
    
    # Key checking template
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
    </style>
    <script>
        document.addEventListener('DOMContentLoaded',function(){
            const key="{{ key }}";
            const status=document.getElementById('status');
            const loader=document.querySelector('.loader');
            status.textContent='Key kontrol ediliyor...';
            fetch('/key_check_status?key='+key)
                .then(r=>r.json())
                .then(data=>{
                    if(data.success){
                        status.textContent='✅ Key doğrulandı! Yönlendiriliyorsunuz...';
                        setTimeout(()=>window.location.href='/panel',2000);
                    }else{
                        status.textContent='❌ '+data.error;
                        status.className='status error';
                        loader.style.display='none';
                    }
                })
                .catch(e=>{
                    status.textContent='❌ Bağlantı hatası';
                    status.className='status error';
                    loader.style.display='none';
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
