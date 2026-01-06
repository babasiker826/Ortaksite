"""
ÖZSOY PANEL - TEMİZ SİSTEM
- Robot doğrulama
- VIP/Free key sistemi
- 70+ API
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
# TÜM API'LER - GÜNCELLENMİŞ (YENİ API'LER EKLENDİ)
# ----------------------------------------------------------------------------
APIS = {
    # Free API'ler
    'adsoyad': {
        'name': 'Ad Soyad TC Sorgu',
        'plan': 'free',
        'endpoint': 'http://45.81.113.22:4040/adsoyad?ad={ad}&soyad={soyad}',
        'params': ['ad', 'soyad']
    },
    'gsmtc': {
        'name': 'GSM → TC Sorgu',
        'plan': 'free',
        'endpoint': 'https://zyrdaware.xyz/api/gsmtc?auth=t.me/zyrdaware&gsm={gsm}',
        'params': ['gsm']
    },
    
    # Yeni Eklenen F3 API'leri
    'tc_sorgu': {
        'name': 'TC Sorgu',
        'plan': 'vip',
        'endpoint': 'http://45.81.113.22:4040/tc?tc={tc}',
        'params': ['tc']
    },
    'aile_sorgu': {
        'name': 'Aile Sorgu',
        'plan': 'vip',
        'endpoint': 'http://45.81.113.22:4040/aile?tc={tc}',
        'params': ['tc']
    },
    'baba_sorgu': {
        'name': 'Baba Sorgu',
        'plan': 'vip',
        'endpoint': 'http://45.81.113.22:4040/baba?tc={tc}',
        'params': ['tc']
    },
    'anne_sorgu': {
        'name': 'Anne Sorgu',
        'plan': 'vip',
        'endpoint': 'http://45.81.113.22:4040/anne?tc={tc}',
        'params': ['tc']
    },
    'adres_sorgu': {
        'name': 'Adres Sorgu (F3)',
        'plan': 'vip',
        'endpoint': 'http://45.81.113.22:4000/f3system/api/adres?tc={tc}&key=F3-TEST-KEY-123',
        'params': ['tc']
    },
    'tcpro_sorgu': {
        'name': 'TC Pro Sorgu',
        'plan': 'vip',
        'endpoint': 'http://45.81.113.22:4000/f3system/api/tcpro?tc={tc}&key=F3-TEST-KEY-123',
        'params': ['tc']
    },
    'hane_sorgu': {
        'name': 'Hane Sorgu',
        'plan': 'vip',
        'endpoint': 'http://45.81.113.22:4000/f3system/api/hane?tc={tc}&key=F3-TEST-KEY-123',
        'params': ['tc']
    },
    'sulale_sorgu': {
        'name': 'Sülale Sorgu',
        'plan': 'vip',
        'endpoint': 'http://45.81.113.22:4000/f3system/api/sulale?tc={tc}&key=F3-TEST-KEY-123',
        'params': ['tc']
    },
    'guncelgsm_sorgu': {
        'name': 'Güncel GSM Sorgu',
        'plan': 'vip',
        'endpoint': 'http://45.81.113.22:4000/f3system/api/guncelgsm?gsm={gsm}&key=F3-TEST-KEY-123',
        'params': ['gsm']
    },
    
    # VIP API'ler - Plaka
    'tc_plaka': {
        'name': 'TC → Plaka Sorgu',
        'plan': 'vip',
        'endpoint': 'https://plakaf3.onrender.com/f3/api/plaka?tc={tc}',
        'params': ['tc']
    },
    'adsoyad_plaka': {
        'name': 'Ad Soyad → Plaka Sorgu',
        'plan': 'vip',
        'endpoint': 'https://plakaf3.onrender.com/f3/api/adsoyadplaka?ad={ad}&soyad={soyad}',
        'params': ['ad', 'soyad']
    },
    'ad_plaka': {
        'name': 'Ad → Plaka Sorgu',
        'plan': 'vip',
        'endpoint': 'https://plakaf3.onrender.com/f3/api/adsoyadplaka?ad={ad}',
        'params': ['ad']
    },
    'soyad_plaka': {
        'name': 'Soyad → Plaka Sorgu',
        'plan': 'vip',
        'endpoint': 'https://plakaf3.onrender.com/f3/api/adsoyadplaka?soyad={soyad}',
        'params': ['soyad']
    },
    
    # VIP API'ler - Papara
    'papara_no': {
        'name': 'Papara No Sorgu',
        'plan': 'vip',
        'endpoint': 'https://paparadata.onrender.com/f3system/api/papara?paparano={paparano}',
        'params': ['paparano']
    },
    'adsoyad_papara': {
        'name': 'Ad Soyad → Papara Sorgu',
        'plan': 'vip',
        'endpoint': 'https://paparadata.onrender.com/f3system/api/papara?ad={ad}&soyad={soyad}',
        'params': ['ad', 'soyad']
    },
    'ad_papara': {
        'name': 'Ad → Papara Sorgu',
        'plan': 'vip',
        'endpoint': 'https://paparadata.onrender.com/f3system/api/papara?ad={ad}',
        'params': ['ad']
    },
    'papara_no_f3': {
        'name': 'Papara No Sorgu (F3)',
        'plan': 'vip',
        'endpoint': 'https://paparadataf3.onrender.com/f3system/api/papara?paparano={paparano}',
        'params': ['paparano']
    },
    'adsoyad_papara_f3': {
        'name': 'Ad Soyad → Papara Sorgu (F3)',
        'plan': 'vip',
        'endpoint': 'https://paparadataf3.onrender.com/f3system/api/papara?ad={ad}&soyad={soyad}',
        'params': ['ad', 'soyad']
    },
    'ad_papara_f3': {
        'name': 'Ad → Papara Sorgu (F3)',
        'plan': 'vip',
        'endpoint': 'https://paparadataf3.onrender.com/f3system/api/papara?ad={ad}',
        'params': ['ad']
    },
    
    # VIP API'ler - Eczane
    'eczane_ad': {
        'name': 'Eczane Adı Sorgu',
        'plan': 'vip',
        'endpoint': 'https://eczanedataf3.onrender.com/f3system/api/eczane?ad={ad}',
        'params': ['ad']
    },
    'eczane_il': {
        'name': 'Eczane İl Sorgu',
        'plan': 'vip',
        'endpoint': 'https://eczanedataf3.onrender.com/f3system/api/eczane?il={il}',
        'params': ['il']
    },
    
    # VIP API'ler - Seri No
    'tc_serino': {
        'name': 'TC → Seri No Sorgu',
        'plan': 'vip',
        'endpoint': 'https://serinodataf3.onrender.com/serino?tc={tc}',
        'params': ['tc']
    },
    'adsoyad_serino': {
        'name': 'Ad Soyad → Seri No Sorgu',
        'plan': 'vip',
        'endpoint': 'https://serinodataf3.onrender.com/serino?ad={ad}&soyad={soyad}',
        'params': ['ad', 'soyad']
    },
    'ad_serino': {
        'name': 'Ad → Seri No Sorgu',
        'plan': 'vip',
        'endpoint': 'https://serinodataf3.onrender.com/serino?ad={ad}',
        'params': ['ad']
    },
    'soyad_serino': {
        'name': 'Soyad → Seri No Sorgu',
        'plan': 'vip',
        'endpoint': 'https://serinodataf3.onrender.com/serino?soyad={soyad}',
        'params': ['soyad']
    },
    'il_ilce_serino': {
        'name': 'İl İlçe → Seri No Sorgu',
        'plan': 'vip',
        'endpoint': 'https://serinodataf3.onrender.com/serino?il={il}&ilce={ilce}',
        'params': ['il', 'ilce']
    },
    'seri_no_sorgu': {
        'name': 'Seri No Sorgu',
        'plan': 'vip',
        'endpoint': 'https://serinodataf3.onrender.com/serino?seri_no={seri_no}',
        'params': ['seri_no']
    },
    'ad_il_limit_serino': {
        'name': 'Ad İl Limit → Seri No Sorgu',
        'plan': 'vip',
        'endpoint': 'https://serinodataf3.onrender.com/serino?ad={ad}&il={il}&limit={limit}',
        'params': ['ad', 'il', 'limit']
    },
    
    # VIP API'ler - Vergi
    'vergi_isim': {
        'name': 'İsim → Vergi Sorgu',
        'plan': 'vip',
        'endpoint': 'https://vergidata-hv43.onrender.com/f3system/api/vergi?isim={isim}',
        'params': ['isim']
    },
    'vergi_ilce_daire': {
        'name': 'İlçe Daire → Vergi Sorgu',
        'plan': 'vip',
        'endpoint': 'https://vergidata-hv43.onrender.com/f3system/api/vergi?ilce={ilce}&vergi_dairesi={vergi_dairesi}',
        'params': ['ilce', 'vergi_dairesi']
    },
    'vergi_no': {
        'name': 'Vergi No Sorgu',
        'plan': 'vip',
        'endpoint': 'https://vergidata-hv43.onrender.com/f3system/api/vergi?vergi_no={vergi_no}',
        'params': ['vergi_no']
    },
    'vergi_limit': {
        'name': 'Vergi Limit Sorgu',
        'plan': 'vip',
        'endpoint': 'https://vergidata-hv43.onrender.com/f3system/api/vergi?limit={limit}',
        'params': ['limit']
    },
    
    # VIP API'ler - Phishing
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
    
    # VIP API'ler - Panel API
    'nufus_sorgu': {
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
    'eczane_recete': {
        'name': 'Eczane Reçete Geçmişi',
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
    'pasaport_sorgu': {
        'name': 'Pasaport Sorgu',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/pasaport/sorgu?tc={tc}',
        'params': ['tc']
    },
    'ehliyet_sorgu': {
        'name': 'Ehliyet Sorgu',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/ehliyet/sorgu?tc={tc}',
        'params': ['tc']
    },
    'arac_sahibi': {
        'name': 'Trafik Araç Sahibi',
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
    'yok_ogrenci': {
        'name': 'YÖK Öğrenci Durum',
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
    'ibb_su_fatura': {
        'name': 'İBB Su Faturası',
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
        'name': 'Turizm Otel Rezervasyon',
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
        'name': 'Spor Federasyon Kayıt',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/spor/federasyon/kayit?tc={tc}',
        'params': ['tc']
    },
    'kutuphane_uye': {
        'name': 'Kütüphane Üye Durum',
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
    'dijital_banka': {
        'name': 'Dijital Banka Müşteri',
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
        'name': 'Çevre Şehirlerarası Ceza',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/cevre/sehirlerarasi-ceza?tc={tc}',
        'params': ['tc']
    },
    'noter_islem': {
        'name': 'Noter Gerçekleşen İşlem',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/noter/gereceklesen-islem?tc={tc}',
        'params': ['tc']
    },
    'avci_lisans': {
        'name': 'Orman Avcı Lisans',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/ormancilik/avci-lisans?tc={tc}',
        'params': ['tc']
    },
    'ucak_bilet': {
        'name': 'Uçak Bilet',
        'plan': 'vip',
        'endpoint': 'https://panelapi.onrender.com/api/v1/udhb/ucak-bilet?tc={tc}',
        'params': ['tc']
    },
    'seyahat_hareket': {
        'name': 'MZK Seyahat Hareket',
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

def vip_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        key_str = session.get('key')
        key = verify_key_string(key_str)
        
        if not key:
            session.clear()
            flash('Lütfen giriş yapın')
            return redirect(url_for('login'))
        
        if not key.is_vip():
            flash('Bu özellik için VIP üyelik gereklidir!')
            return redirect(url_for('abonelik_page'))
        
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
    
    key_str = session.get('key')
    key = verify_key_string(key_str)
    
    return jsonify({
        'success': True,
        'total_apis': total,
        'free_apis': free,
        'vip_apis': vip,
        'user_can_access': total if key.is_vip() else free,
        'is_vip': key.is_vip()
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
# BAŞLATMA
# ----------------------------------------------------------------------------
if __name__ == '__main__':
    init_db()
    print("\n" + "="*60)
    print("🔥 ÖZSOY PANEL - TEMİZ SİSTEM")
    print("="*60)
    print(f"🔐 FREE Key: {SABIT_FREE_KEY}")
    print(f"🌐 URL: http://127.0.0.1:5000")
    print(f"📊 Toplam API: {len(APIS)}")
    print(f"🆓 Free API: {len([a for a in APIS.values() if a['plan'] == 'free'])}")
    print(f"👑 VIP API: {len([a for a in APIS.values() if a['plan'] == 'vip'])}")
    print("="*60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
