"""
ÖZSOY PANEL - API KONTROLLÜ KEY SİSTEMİ
- API üzerinden key kontrol
- Otomatik key kontrol
- Tüm API'ler ile
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
import asyncio

from flask import Flask, request, session, jsonify, render_template, redirect, url_for, flash, g
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

# ----------------------------------------------------------------------------
# FLASK APP
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

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

db = SQLAlchemy(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per day", "220 per hour"],
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
                api_created=False
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
                api_created=False
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

def check_key_via_api(kstr):
    """API üzerinden key kontrolü yap"""
    if not kstr or len(kstr) != 20:
        return {'success': False, 'error': 'Geçersiz key formatı'}

    try:
        url = f"{API_CHECK_URL}?key={kstr}"
        print(f"[API] Key kontrolü başlatılıyor: {url}")

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        response = requests.get(url, headers=headers, timeout=10)
        print(f"[API] Yanıt durumu: {response.status_code}")
        print(f"[API] Yanıt text: {response.text}")

        if response.status_code == 200:
            try:
                data = response.json()
                print(f"[API] Yanıt JSON: {data}")

                # API yanıt formatı: {"bitis":"2026-01-28T18:58:01.045965","durum":"aktif"}
                if data.get('durum') == 'aktif':
                    return {
                        'success': True,
                        'key': kstr,
                        'status': 'active',
                        'expires_at': data.get('bitis')
                    }
                elif data.get('durum') == 'pasif':
                    return {'success': False, 'error': 'Key pasif veya süresi dolmuş'}
                else:
                    # "durum" anahtarı yoksa da başarılı say
                    return {'success': True, 'key': kstr, 'status': 'active', 'expires_at': data.get('bitis')}
            except Exception as e:
                print(f"[API] JSON parse hatası: {e}")
                # Text formatını parse et
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
        return {'success': False, 'error': 'API yanıt vermedi (timeout)'}
    except requests.ConnectionError:
        return {'success': False, 'error': 'API sunucusuna bağlanılamadı'}
    except Exception as e:
        print(f"[API] Kontrol hatası: {e}")
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
        client_ip = get_client_ip()

        if 'key' not in session:
            return redirect(url_for('login'))

        key_str = session.get('key')

        key = verify_key_string(key_str)

        if not key and key_str != SABIT_FREE_KEY and len(key_str) == 20:
            if request.method == 'GET' and request.endpoint == 'panel':
                return render_template('key_checking.html', key=key_str)

            try:
                # API'den kontrol et
                result = check_key_via_api(key_str)

                if result.get('success'):
                    # DB'de key var mı kontrol et
                    key = Key.query.filter_by(key=key_str).first()

                    if not key:
                        # Yeni key oluştur
                        key = Key(
                            key=key_str,
                            plan='vip',
                            created_at=datetime.now(),
                            expires_at=None,  # API'den gelirse tarihi ayarla
                            active=True,
                            notes='API üzerinden doğrulandı',
                            owner='API User',
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
                    session['login_ip'] = client_ip
                    session.modified = True
                else:
                    session.clear()
                    flash(f'Key geçersiz: {result.get("error", "Bilinmeyen hata")}')
                    return redirect(url_for('login'))

            except Exception as e:
                print(f"[Key Check] API kontrol hatası: {e}")
                session.clear()
                flash('Key doğrulama hatası')
                return redirect(url_for('login'))

        if not key:
            session.clear()
            flash('Key geçersiz veya süresi dolmuş')
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

@app.route('/')
def index():
    return redirect(url_for('robot_dogrulama'))

@app.route('/robot_dogrulama')
@limiter.limit("10 per minute")
def robot_dogrulama():
    next_page = request.args.get('next', '/login')
    return render_template('robot_dogrulama.html', next_page=next_page)

@app.route('/keneviz_challenge', methods=['POST'])
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
        session.modified = True

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
        return render_template('login.html')

    key_str = request.form.get('key', '').strip()

    if not key_str:
        flash('Key giriniz!')
        return redirect(url_for('login'))

    # Eğer FREE key ise direk panele yönlendir
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
        session['is_vip'] = key.plan != 'free'
        session['login_ip'] = g.client_ip

        session.pop('keneviz_verified', None)
        session.modified = True

        return redirect(url_for('panel'))

    # 20 haneli key değilse hata
    if len(key_str) != 20:
        flash('Geçersiz key formatı! 20 haneli VIP key veya FREE key girin.')
        return redirect(url_for('login'))

    # Önce local DB'de kontrol et
    key = verify_key_string(key_str)

    # Local DB'de varsa ve aktifse direk panele yönlendir
    if key and key.active and not key.is_expired():
        session['key'] = key.key
        session['plan'] = key.plan
        session['key_id'] = key.id
        session['logged_in'] = True
        session['username'] = f"user{key.id}"
        session['is_vip'] = key.plan != 'free'
        session['login_ip'] = g.client_ip

        session.pop('keneviz_verified', None)
        session.modified = True

        return redirect(url_for('panel'))

    # Local DB'de yoksa veya geçersizse kontrol sayfasına yönlendir

@app.route('/key_check_status')
@limiter.limit("5 per minute")
def key_check_status():
    key_str = request.args.get('key', '')

    if not key_str or len(key_str) != 20:
        return jsonify({'success': False, 'error': 'Geçersiz key formatı'})

    try:
        print(f"[Key Check] API kontrolü başlatılıyor: {key_str}")

        # API'den kontrol et
        result = check_key_via_api(key_str)

        print(f"[Key Check] API sonucu success: {result.get('success')}")
        print(f"[Key Check] API sonucu: {result}")

        if result.get('success'):
            key = Key.query.filter_by(key=key_str).first()

            if not key:
                # Bitiş tarihini parse et
                expires_at = None
                expiry_str = result.get('expires_at')
                if expiry_str:
                    try:
                        # Tarihi parse et: "2026-01-28T18:58:01.045965"
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
                    api_key_id=f"api_{key_str[:10]}"
                )
                db.session.add(key)
                db.session.commit()
                print(f"[Key Check] DB'ye yeni VIP key eklendi: {key_str}")

            # SESSION'A KAYDET - BU ÇOK ÖNEMLİ!
            session['key'] = key.key
            session['plan'] = key.plan
            session['key_id'] = key.id
            session['logged_in'] = True
            session['username'] = f"user{key.id}"
            session['is_vip'] = True
            session['login_ip'] = get_client_ip()
            session.modified = True

            print(f"[Key Check] Session oluşturuldu: key={key.key}, vip={True}")

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
            print(f"[Key Check] Key doğrulanamadı: {error_msg}")

            return jsonify({
                'success': False,
                'error': error_msg,
                'message': 'Geçersiz key veya API yanıt vermedi'
            })

    except Exception as e:
        print(f"[Key Check] Status hatası: {e}")
        import traceback
        traceback.print_exc()
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

    # Bugünkü sorgu sayısını hesapla (basit bir yaklaşım)
    from datetime import date
    today = date.today()
    today_calls = key.usage_count if key.last_used and key.last_used.date() == today else 0

    # API istatistikleri
    total_apis = len(APIS)
    free_apis = len([a for a in APIS.values() if a['plan'] == 'free'])
    vip_apis = len([a for a in APIS.values() if a['plan'] == 'vip'])

    # VIP kullanıcı için erişilebilir API sayısı
    user_apis = total_apis if key.is_vip() else free_apis

    # Template'e tüm değişkenleri gönder
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
        last_api=key.last_used,  # Basit yaklaşım, ayrı bir API log tablosu olabilir
        free_key=SABIT_FREE_KEY
    )

@app.route('/sorgu.html')
@login_required
@limiter.limit("20 per minute")
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
        flash(f"Bu API için VIP üyelik gereklidir: {api_info['name']}")
        return redirect(url_for('abonelik_page'))

    # Template'e API bilgilerini gönder
    return render_template('sorgu.html',
                         api_id=api_id,
                         api_info=api_info,
                         is_vip=key.is_vip(),
                         username=session.get('username', 'Misafir'))

@app.route('/abonelik.html')
def abonelik_page():
    return render_template('abonelik.html')

# ----------------------------------------------------------------------------
# API ENDPOINT'LERİ
# ----------------------------------------------------------------------------
@app.route('/api/user')
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
        'username': session.get('username', f"user{key.id}")
    })

@app.route('/api/list')
@login_required
@limiter.limit("10 per minute")
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
        return jsonify({
            'success': False,
            'error': f'Bu API için VIP üyelik gereklidir. Mevcut planınız: {user_plan}',
            'redirect': '/abonelik.html',
            'api_name': APIS[api_id]['name'],
            'user_plan': user_plan,
            'required_plan': 'vip'
        }), 403

    api_params = APIS[api_id]['params']
    for param in api_params:
        param_value = data.get(param, '')
        if not param_value:
            return jsonify({'success': False, 'error': f'{param} parametresi gereklidir'}), 400

    api_endpoint = APIS[api_id]['endpoint']

    filled_endpoint = api_endpoint
    for param in api_params:
        param_value = data.get(param, '')
        filled_endpoint = filled_endpoint.replace(f'{{{param}}}', str(param_value))

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
            'X-Requested-With': 'XMLHttpRequest'
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
            return jsonify({
                'success': False,
                'error': f'API hatası: {response.status_code}',
                'response': response.text[:500] if response.text else 'No response text'
            }), response.status_code
    except requests.Timeout:
        return jsonify({'success': False, 'error': 'API yanıt vermedi (timeout). Lütfen daha sonra tekrar deneyin.'}), 504
    except requests.ConnectionError:
        return jsonify({'success': False, 'error': 'API sunucusuna bağlanılamadı.'}), 503
    except requests.RequestException as e:
        return jsonify({'success': False, 'error': f'İstek hatası: {str(e)}'}), 500

# ----------------------------------------------------------------------------
# KEY CHECKING.HTML DOSYASINI OLUŞTURMA
# ----------------------------------------------------------------------------
def create_key_checking_template():
    templates_dir = os.path.join(BASE_DIR, 'templates')
    os.makedirs(templates_dir, exist_ok=True)

    key_checking_html = '''<!DOCTYPE html>
<html>
<head>
    <title>Key Kontrol Ediliyor</title>
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
        }

        .details p {
            margin: 8px 0;
        }

        .success {
            color: #10b981;
            font-weight: 600;
        }

        .error {
            color: #ef4444;
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
        }

        .api-icon {
            font-size: 40px;
            margin-bottom: 20px;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.1); }
            100% { transform: scale(1); }
        }

        .steps {
            display: flex;
            justify-content: space-between;
            margin: 20px 0;
        }

        .step {
            text-align: center;
            flex: 1;
            padding: 10px;
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
        }

        .step-text {
            font-size: 12px;
            color: #94a3b8;
        }

        .step.active .step-number {
            background: #10b981;
        }

        .step.active .step-text {
            color: #10b981;
            font-weight: 600;
        }
    </style>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const key = "{{ key }}";
            const statusElement = document.getElementById('status-message');
            const loader = document.querySelector('.loader');
            const steps = document.querySelectorAll('.step');

            let currentStep = 0;

            function updateStep(stepIndex) {
                steps.forEach((step, index) => {
                    if (index === stepIndex) {
                        step.classList.add('active');
                    } else {
                        step.classList.remove('active');
                    }
                });
                currentStep = stepIndex;
            }

            updateStep(0);
            statusElement.innerHTML = '🔍 API sunucusuna bağlanılıyor...';

            setTimeout(() => {
                updateStep(1);
                statusElement.innerHTML = '📤 Key sorgusu gönderiliyor...';

                setTimeout(() => {
                    updateStep(2);
                    statusElement.innerHTML = '⏳ Yanıt bekleniyor...';

                    checkKeyStatus(key);
                }, 1500);
            }, 1500);

            function checkKeyStatus(key) {
                console.log('Key kontrol başlatılıyor:', key);
                fetch('/key_check_status?key=' + key)
                    .then(response => response.json())
                    .then(data => {
                        console.log('Key kontrol sonucu:', data);
                        if (data.success) {
                            updateStep(3);
                            statusElement.innerHTML = '✅ <span class="success">Key başarıyla doğrulandı!</span>';
                            statusElement.className = 'status-message success';
                            loader.style.display = 'none';

                            document.getElementById('success-message').style.display = 'block';

                            setTimeout(() => {
                                window.location.href = '/panel';
                            }, 2000);
                        } else {
                            updateStep(3);
                            statusElement.innerHTML = '❌ <span class="error">Key doğrulanamadı: ' + (data.error || 'Bilinmeyen hata') + '</span>';
                            statusElement.className = 'status-message error';
                            loader.style.display = 'none';

                            document.getElementById('error-message').innerHTML =
                                '<p>Hata: ' + (data.error || 'Key geçersiz') + '</p>' +
                                '<button onclick="window.location.href=\'/login\'" style="background:#ef4444;color:white;border:none;padding:10px 20px;border-radius:5px;margin-top:15px;cursor:pointer;font-size:14px;">↩️ Giriş Sayfasına Dön</button>';
                            document.getElementById('error-message').style.display = 'block';
                        }
                    })
                    .catch(error => {
                        console.error('Key kontrol hatası:', error);
                        updateStep(3);
                        statusElement.innerHTML = '❌ <span class="error">Bağlantı hatası: ' + error + '</span>';
                        statusElement.className = 'status-message error';
                        loader.style.display = 'none';

                        document.getElementById('error-message').innerHTML =
                            '<p>Sunucuyla bağlantı kurulamadı. Lütfen internet bağlantınızı kontrol edin.</p>' +
                            '<button onclick="window.location.href=\'/login\'" style="background:#ef4444;color:white;border:none;padding:10px 20px;border-radius:5px;margin-top:15px;cursor:pointer;font-size:14px;">↩️ Giriş Sayfasına Dön</button>';
                        document.getElementById('error-message').style.display = 'block';
                    });
            }
        });
    </script>
</head>
<body>
    <div class="container">
        <div class="api-icon">🔐</div>
        <div class="loader"></div>

        <h1>🔐 VIP Key Kontrol Ediliyor</h1>

        <div class="key-display">
            {{ key }}
        </div>

        <div class="steps">
            <div class="step">
                <div class="step-number">1</div>
                <div class="step-text">Bağlanılıyor</div>
            </div>
            <div class="step">
                <div class="step-number">2</div>
                <div class="step-text">Sorgu Gönderiliyor</div>
            </div>
            <div class="step">
                <div class="step-number">3</div>
                <div class="step-text">Yanıt Bekleniyor</div>
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
            <p>📋 <strong>İşlem Detayları:</strong></p>
            <p>• API sunucusuna bağlanılıyor...</p>
            <p>• Key doğrulama sorgusu gönderiliyor...</p>
            <p>• Yanıt bekleniyor...</p>
            <p>• Sonuçlar analiz ediliyor...</p>
        </div>

        <div id="success-message" class="redirect-notice" style="display: none;">
            ✅ Key başarıyla doğrulandı! Panel sayfasına yönlendiriliyorsunuz...
        </div>

        <div id="error-message" style="display: none; margin-top: 20px; text-align: center;"></div>

        <div style="margin-top: 30px; font-size: 12px; color: #64748b;">
            <p>⚠️ Not: Bu işlem harici API üzerinden yapılmaktadır. İnternet bağlantınızın stabil olduğundan emin olun.</p>
            <p>🔄 İşlem genellikle 3-5 saniye sürmektedir.</p>
        </div>
    </div>
</body>
</html>'''

    key_checking_path = os.path.join(templates_dir, 'key_checking.html')
    with open(key_checking_path, 'w', encoding='utf-8') as f:
        f.write(key_checking_html)

    print("[INFO] key_checking.html template oluşturuldu")

# ----------------------------------------------------------------------------
# BAŞLATMA
# ----------------------------------------------------------------------------
if __name__ == '__main__':
    init_db()
    create_key_checking_template()

    print("\n" + "="*60)
    print("ÖZSOY PANEL - API KONTROLLÜ KEY SİSTEMİ")
    print("="*60)
    print(f"🔐 Key Checking Sistemi: AKTİF")
    print(f"🌐 API Kontrol URL: {API_CHECK_URL}")
    print(f"📊 Toplam API: {len(APIS)}")
    print(f"🆓 Free API: {len([a for a in APIS.values() if a['plan'] == 'free'])}")
    print(f"👑 VIP API: {len([a for a in APIS.values() if a['plan'] == 'vip'])}")
    print(f"📱 URL: http://127.0.0.1:5000")
    print(f"🔑 FREE Key: {SABIT_FREE_KEY}")
    print("="*60 + "\n")

    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') != 'production'

    app.run(
        debug=debug_mode,
        host='0.0.0.0',
        port=port,
        threaded=True
)
