import os
import sqlite3
from fastapi import FastAPI, Query, Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
import bcrypt
import requests
import uuid
import math
import random

app = FastAPI()

HEADERS = {
    'User-Agent': 'HemenKuryeApp/1.0 (iletisim@hemenkurye.ornek)'
}

# --- BULUT UYUMLU VERİTABANI YOLU ---
# Render veya herhangi bir sunucuda sorunsuz çalışması için yerel klasör
DB_PATH = "hemenkurye.db"

def hash_password(password: str) -> str:
    safe_pwd = password.encode('utf-8')[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(safe_pwd, salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    safe_pwd = plain_password.encode('utf-8')[:72]
    return bcrypt.checkpw(safe_pwd, hashed_password.encode('utf-8'))

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            password TEXT NOT NULL,
            otp_code TEXT,
            is_verified INTEGER DEFAULT 0
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS siparisler (
            id TEXT PRIMARY KEY,
            user_email TEXT NOT NULL,
            hizmet_tipi TEXT NOT NULL,
            arac TEXT NOT NULL,
            agirlik INTEGER NOT NULL,
            cikis_adres TEXT NOT NULL,
            cikis_detay TEXT NOT NULL,
            gonderici_isim TEXT NOT NULL,
            gonderici_tel TEXT NOT NULL,
            alici_isim TEXT NOT NULL,
            alici_adres TEXT NOT NULL,
            alici_detay TEXT NOT NULL,
            alici_tel TEXT NOT NULL,
            tutar REAL NOT NULL,
            mesafe REAL NOT NULL,
            durum TEXT DEFAULT 'Atama Bekliyor',
            kurye_email TEXT,
            fotograf_yolu TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS destek_mesajlari (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            gonderen TEXT NOT NULL,
            mesaj TEXT NOT NULL,
            zaman DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_db()

# Simüle e-posta fonksiyonu (Render'da hata vermemesi için)
def send_otp_email(email: str, code: str):
    print(f"--- OTP GÖNDERİLDİ ({email}): {code} ---")
    return True

class UserRegister(BaseModel):
    name: str
    email: EmailStr
    phone: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserVerify(BaseModel):
    email: EmailStr
    otp_code: str

class UserUpdate(BaseModel):
    email: EmailStr
    name: str
    phone: str

class SiparisOlusturRequest(BaseModel):
    user_email: str
    hizmet_tipi: str
    arac: str
    agirlik: int
    cikis_adres: str
    cikis_detay: str
    cikis_lat: float
    cikis_lon: float
    gonderici_isim: str
    gonderici_tel: str
    alici_isim: str
    alici_adres: str
    alici_detay: str
    alici_lat: float
    alici_lon: float
    alici_tel: str

class DestekMesajRequest(BaseModel):
    user_email: str
    gonderen: str
    mesaj: str

@app.post("/api/register")
def register(user: UserRegister, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT id, is_verified FROM users WHERE email = ?", (user.email,))
    existing_user = cursor.fetchone()
    
    hashed_password = hash_password(user.password)
    
    if existing_user:
        if existing_user["is_verified"] == 1:
            raise HTTPException(status_code=400, detail="Bu e-posta adresi zaten kayıtlı ve doğrulanmış.")
        else:
            otp_code = str(random.randint(100000, 999999))
            cursor.execute(
                "UPDATE users SET name = ?, phone = ?, password = ?, otp_code = ? WHERE email = ?",
                (user.name, user.phone, hashed_password, otp_code, user.email)
            )
            db.commit()
            send_otp_email(user.email, otp_code)
            return {"message": "Kayıt güncellendi. Lütfen e-postanıza gelen doğrulama kodunu girin.", "requires_verification": True}

    otp_code = str(random.randint(100000, 999999))
    cursor.execute(
        "INSERT INTO users (name, email, phone, password, otp_code, is_verified) VALUES (?, ?, ?, ?, ?, 0)",
        (user.name, user.email, user.phone, hashed_password, otp_code)
    )
    db.commit()
    send_otp_email(user.email, otp_code)

    return {"message": "Kayıt başarılı. Lütfen e-postanıza gönderilen 6 haneli kodu girin.", "requires_verification": True}

@app.post("/api/verify-email")
def verify_email(data: UserVerify, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (data.email,))
    db_user = cursor.fetchone()

    if not db_user:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı.")

    if db_user["is_verified"] == 1:
        return {"message": "Bu hesap zaten doğrulanmış."}

    if db_user["otp_code"] != data.otp_code:
        raise HTTPException(status_code=400, detail="Hatalı doğrulama kodu.")

    cursor.execute("UPDATE users SET is_verified = 1, otp_code = NULL WHERE email = ?", (data.email,))
    db.commit()

    return {"message": "E-posta başarıyla doğrulandı! Şimdi giriş yapabilirsiniz."}

@app.post("/api/login")
def login(user: UserLogin, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (user.email,))
    db_user = cursor.fetchone()
    
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=400, detail="E-posta veya şifre hatalı.")
    
    if db_user["is_verified"] == 0:
        raise HTTPException(status_code=403, detail="Lütfen önce e-posta adresinizi doğrulayın.")
    
    return {
        "message": "Giriş başarılı", 
        "user": {
            "id": db_user["id"],
            "name": db_user["name"],
            "email": db_user["email"],
            "phone": db_user["phone"]
        }
    }

@app.post("/api/update-profile")
def update_profile(data: UserUpdate, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("UPDATE users SET name = ?, phone = ? WHERE email = ?", (data.name, data.phone, data.email))
    db.commit()
    
    cursor.execute("SELECT * FROM users WHERE email = ?", (data.email,))
    db_user = cursor.fetchone()
    
    return {
        "message": "Profil başarıyla güncellendi",
        "user": {
            "id": db_user["id"],
            "name": db_user["name"],
            "email": db_user["email"],
            "phone": db_user["phone"]
        }
    }

@app.get("/api/ara")
def adres_ara(q: str = Query(...)):
    try:
        url = f"https://nominatim.openstreetmap.org/search?q={q}+Istanbul+Turkey&format=json&limit=5&countrycodes=tr"
        response = requests.get(url, headers=HEADERS, timeout=3)
        if response.status_code == 200:
            return response.json()
        return []
    except Exception as e:
        return []

def mesafe_hesapla(lat1, lon1, lat2, lon2):
    try:
        osrm_url = f"http://router.project-osrm.org/route/v1/driving/{lon1},{lat1};{lon2},{lat2}?overview=false"
        response = requests.get(osrm_url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            if "routes" in data and len(data["routes"]) > 0:
                return round(data["routes"][0]["distance"] / 1000.0, 2)
    except:
        pass

    try:
        R = 6371.0
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
        c = 2 * math.asin(math.sqrt(a))
        return round(max(c * R * 1.35, 1.5), 2)
    except:
        return 3.0

class FiyatHesaplaRequest(BaseModel):
    cikis_lat: float
    cikis_lon: float
    alici_lat: float
    alici_lon: float
    hizmet_tipi: str = "Hızlı Ekspres (45 Dk)"
    arac: str = "Motor"
    agirlik: int = 2

@app.post("/api/fiyat-hesapla")
def fiyat_hesapla_api(data: FiyatHesaplaRequest):
    mesafe = mesafe_hesapla(data.cikis_lat, data.cikis_lon, data.alici_lat, data.alici_lon)
    carpan = 35 if data.arac.strip().capitalize() == "Motor" else 60
    baz_ucret = 60 if data.arac.strip().capitalize() == "Motor" else 120
    tutar = baz_ucret + (mesafe * carpan) + (data.agirlik * 6)
    
    if data.hizmet_tipi == "Hızlı Ekspres (45 Dk)":
        tutar *= 1.40
    elif data.hizmet_tipi == "Ekonomik Planlı":
        tutar *= 0.70

    return {"tutar": round(tutar, 2), "mesafe": round(mesafe, 2)}

@app.post("/api/siparis-olustur")
def siparis_olustur_api(data: SiparisOlusturRequest, db: sqlite3.Connection = Depends(get_db)):
    mesafe = mesafe_hesapla(data.cikis_lat, data.cikis_lon, data.alici_lat, data.alici_lon)
    siparis_id = str(uuid.uuid4())[:6].upper()
    
    carpan = 35 if data.arac=="Motor" else 60
    baz_ucret = 60 if data.arac=="Motor" else 120
    tutar = baz_ucret + (mesafe * carpan) + (data.agirlik * 6)
    if data.hizmet_tipi == "Hızlı Ekspres (45 Dk)":
        tutar *= 1.40
    elif data.hizmet_tipi == "Ekonomik Planlı":
        tutar *= 0.70

    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO siparisler (id, user_email, hizmet_tipi, arac, agirlik, cikis_adres, cikis_detay, gonderici_isim, gonderici_tel, alici_isim, alici_adres, alici_detay, alici_tel, tutar, mesafe, durum)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Atama Bekliyor')
    """, (siparis_id, data.user_email, data.hizmet_tipi, data.arac, data.agirlik, data.cikis_adres, data.cikis_detay, data.gonderici_isim, data.gonderici_tel, data.alici_isim, data.alici_adres, data.alici_detay, data.alici_tel, round(tutar, 2), mesafe))
    db.commit()

    return {"message": "Sipariş başarıyla oluşturuldu", "siparis_id": siparis_id, "tutar": round(tutar, 2), "mesafe": mesafe}

@app.get("/api/siparislerim")
def siparislerim_api(email: str, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM siparisler WHERE user_email = ?", (email,))
    rows = cursor.fetchall()
    return [dict(row) for row in rows]

class SiparisIptalRequest(BaseModel):
    siparis_id: str
    neden: str

@app.post("/api/siparis-iptal")
def siparis_iptal_api(data: SiparisIptalRequest, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("UPDATE siparisler SET durum = ? WHERE id = ?", (f"İptal Edildi ({data.neden})", data.siparis_id))
    db.commit()
    return {"message": "Sipariş başarıyla iptal edildi."}

class SiparisDuzenleRequest(BaseModel):
    siparis_id: str
    cikis_adres: str
    cikis_detay: str
    gonderici_isim: str
    gonderici_tel: str
    alici_adres: str
    alici_detay: str
    alici_isim: str
    alici_tel: str

@app.post("/api/siparis-duzenle")
def siparis_duzenle_api(data: SiparisDuzenleRequest, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("""
        UPDATE siparisler 
        SET cikis_adres = ?, cikis_detay = ?, gonderici_isim = ?, gonderici_tel = ?, 
            alici_adres = ?, alici_detay = ?, alici_isim = ?, alici_tel = ? 
        WHERE id = ?
    """, (data.cikis_adres, data.cikis_detay, data.gonderici_isim, data.gonderici_tel, 
          data.alici_adres, data.alici_detay, data.alici_isim, data.alici_tel, data.siparis_id))
    db.commit()
    return {"message": "Sipariş bilgileri güncellendi."}

@app.get("/api/destek-mesajlari")
def destek_mesajlari_getir(email: str, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM destek_mesajlari WHERE user_email = ? ORDER BY id ASC", (email,))
    rows = cursor.fetchall()
    return [dict(row) for row in rows]

@app.post("/api/destek-mesaj-gonder")
def destek_mesaj_gonder(data: DestekMesajRequest, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("INSERT INTO destek_mesajlari (user_email, gonderen, mesaj) VALUES (?, ?, ?)", (data.user_email, data.gonderen, data.mesaj))
    db.commit()

    if data.gonderen == "Kullanıcı":
        bot_cevap = "HemenKurye Akıllı Asistan: Talebinizi aldım. Sevkiyat veya kurye konum durumunuzla ilgili yardımcı olabilirim. Canlı operasyon ekibimize bağlanmak için 'Admin' yazabilirsiniz."
        text_lower = data.mesaj.lower()
        if "admin" in text_lower or "operasyon" in text_lower or "temsilci" in text_lower:
            bot_cevap = "Sizi hemen kıdemli operasyon sorumlumuza aktarıyorum, lütfen hattan ayrılmayın..."
            cursor.execute("INSERT INTO destek_mesajlari (user_email, gonderen, mesaj) VALUES (?, ?, ?)", (data.user_email, "Admin", "Merhaba, ben Operasyon Yöneticisi Serkan. Gönderinizle ilgili size nasıl yardımcı olabilirim?"))
        elif "fiyat" in text_lower or "ücret" in text_lower:
            bot_cevap = "Fiyatlandırmalarımız mesafe, seçilen araç sınıfı ve paket ağırlığı baz alınarak şeffaf biçimde hesaplanır."

        cursor.execute("INSERT INTO destek_mesajlari (user_email, gonderen, mesaj) VALUES (?, ?, ?)", (data.user_email, "Bot", bot_cevap))
        db.commit()

    return {"message": "Mesaj iletildi"}

@app.get("/", response_class=HTMLResponse)
def index():
    return """<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>HemenKurye - Profesyonel Lojistik Paneli</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <style>
        :root {
            --hk-kirmizi: #D32F2F;
            --hk-kirmizi-koyu: #9A0007;
            --hk-kirmizi-acik: #FFEBEE;
            --hk-dark: #1F2937;
        }
        body { background-color: #f8fafc; color: var(--hk-dark); padding-bottom: 85px; font-family: system-ui, -apple-system, sans-serif; }
        .bg-kirmizi { background-color: var(--hk-kirmizi) !important; }
        .text-kirmizi { color: var(--hk-kirmizi) !important; }
        .btn-kirmizi { background-color: var(--hk-kirmizi); color: #fff; border: none; font-weight: 600; }
        .btn-kirmizi:hover { background-color: var(--hk-kirmizi-koyu); color: #fff; }
        .nav-pills .nav-link.active { background-color: var(--hk-kirmizi) !important; color: #fff !important; font-weight: bold; }
        .nav-pills .nav-link { color: #4b5563; font-weight: 500; }
        .autocomplete-items { position: absolute; border: 1px solid #cbd5e1; z-index: 99; top: 100%; left: 0; right: 0; background-color: #fff; max-height: 250px; overflow-y: auto; box-shadow: 0px 10px 15px -3px rgba(0,0,0,0.1); border-radius: 0 0 10px 10px; }
        .autocomplete-items div { padding: 12px; cursor: pointer; background-color: #fff; border-bottom: 1px solid #f1f5f9; font-size: 13px; }
        .autocomplete-items div:hover { background-color: var(--hk-kirmizi-acik); color: var(--hk-kirmizi); }
        .autocomplete-wrapper { position: relative; }
        #harita { height: 240px; border-radius: 12px; margin-top: 10px; border: 2px solid #e2e8f0; }
        .bottom-nav { position: fixed; bottom: 0; left: 0; right: 0; background: #fff; border-top: 1px solid #e2e8f0; display: flex; justify-content: space-around; padding: 12px 0; z-index: 1000; box-shadow: 0 -4px 20px rgba(0,0,0,0.05); }
        .bottom-nav button { background: none; border: none; font-size: 11px; color: #64748b; font-weight: 600; display: flex; flex-direction: column; align-items: center; transition: 0.2s; }
        .bottom-nav button.active { color: var(--hk-kirmizi); transform: translateY(-2px); }
        .bottom-nav button span.icon { font-size: 22px; margin-bottom: 3px; }
        .destek-modal { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: #fff; z-index: 2000; flex-direction: column; }
        .stat-card { border: none; border-radius: 16px; background: #fff; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); }
    </style>
</head>
<body>
    <div class="container" style="max-width: 650px; margin-top: 25px;">
        <div id="auth-container" class="card shadow-lg p-4 mb-4 border-0 rounded-5 bg-white">
            <div class="text-center mb-4">
                <div class="d-inline-block p-3 rounded-4 shadow-sm" style="background-color: var(--hk-kirmizi-acik);">
                    <span class="fs-3 fw-black text-kirmizi" style="letter-spacing: -1px;">🚨 HEMENKURYE</span>
                </div>
                <p class="text-muted small mt-2 fw-semibold">Kurumsal Ekspres Dağıtım & Kurye Paneli</p>
            </div>
            
            <ul class="nav nav-pills nav-fill mb-4 p-1 bg-light rounded-pill" id="authTab" role="tablist">
                <li class="nav-item"><button class="nav-link active rounded-pill py-2" id="login-tab" data-bs-toggle="pill" data-bs-target="#login-content" type="button">Oturum Aç</button></li>
                <li class="nav-item"><button class="nav-link rounded-pill py-2" id="register-tab" data-bs-toggle="pill" data-bs-target="#register-content" type="button">Yeni Hesap</button></li>
            </ul>
            
            <div class="tab-content">
                <div class="tab-pane fade show active" id="login-content">
                    <form onsubmit="girisYap(event)">
                        <div class="mb-3"><label class="form-label small fw-bold text-secondary">E-posta</label><input type="email" class="form-control rounded-4 py-2 border-2" id="login_email" required></div>
                        <div class="mb-4"><label class="form-label small fw-bold text-secondary">Şifre</label><input type="password" class="form-control rounded-4 py-2 border-2" id="login_password" required></div>
                        <button type="submit" class="btn btn-kirmizi w-100 py-3 rounded-4 shadow-sm">Giriş Yap</button>
                    </form>
                </div>
                <div class="tab-pane fade" id="register-content">
                    <form id="register-form" onsubmit="kayitOl(event)">
                        <div class="mb-2"><label class="form-label small fw-bold text-secondary">Ad Soyad</label><input type="text" class="form-control rounded-4 py-2 border-2" id="reg_name" required></div>
                        <div class="mb-2"><label class="form-label small fw-bold text-secondary">E-posta</label><input type="email" class="form-control rounded-4 py-2 border-2" id="reg_email" required></div>
                        <div class="mb-2"><label class="form-label small fw-bold text-secondary">Telefon</label><input type="tel" class="form-control rounded-4 py-2 border-2" id="reg_phone" required></div>
                        <div class="mb-3"><label class="form-label small fw-bold text-secondary">Şifre</label><input type="password" class="form-control rounded-4 py-2 border-2" id="reg_password" required></div>
                        <button type="submit" class="btn btn-kirmizi w-100 py-3 rounded-4 shadow-sm">Kayıt Ol</button>
                    </form>
                    <div id="verify-section" style="display: none;" class="mt-3 border-top pt-3">
                        <div class="alert alert-danger py-2 small fw-bold text-center">6 haneli kod:</div>
                        <input type="text" class="form-control text-center fw-bold fs-3 rounded-4 border-2 mb-3" id="otp_code_input" maxlength="6">
                        <button type="button" onclick="dogrulaKodu()" class="btn btn-dark w-100 py-3 rounded-4 fw-bold">Doğrula</button>
                    </div>
                </div>
            </div>
        </div>

        <div id="app-container" style="display: none;">
            <div id="page-gonderiler" class="page-content">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div><h4 class="fw-bold m-0 text-dark">Operasyon Paneli</h4><p class="text-muted small m-0">Canlı kurye ağı</p></div>
                    <span class="badge bg-kirmizi px-3 py-2 rounded-pill shadow-sm">Aktif</span>
                </div>
                <h5 class="fw-bold mb-3 text-secondary">Hizmet Seçin</h5>
                <div class="card border-0 shadow-sm p-3 mb-3 rounded-4" onclick="hizmetSec('Hızlı Ekspres (45 Dk)')" style="cursor: pointer; border-left: 5px solid var(--hk-kirmizi) !important;">
                    <h6 class="fw-bold text-dark mb-1">🚀 Hızlı Ekspres (45 Dakika)</h6>
                    <p class="text-muted small mb-0">En yakın saha kuryesi yönlendirilir.</p>
                </div>
                <h5 class="fw-bold mb-3 text-secondary">Aktif Sevkiyatlarım</h5>
                <div id="aktif-siparisler-listesi"><div class="alert alert-light border rounded-4 text-center text-muted py-4">Yükleniyor...</div></div>
            </div>

            <div id="page-yenigonderi" class="page-content" style="display: none;">
                <h4 class="fw-bold mb-3 text-dark">Yeni Kurye Çağır</h4>
                <div class="card shadow-sm p-4 border-0 rounded-5 bg-white">
                    <form onsubmit="siparisGonder(event)">
                        <input type="hidden" id="cikis_lat"><input type="hidden" id="cikis_lon">
                        <input type="hidden" id="alici_lat"><input type="hidden" id="alici_lon">
                        <div class="mb-3"><label class="form-label fw-bold small text-secondary">Kategori</label><input type="text" class="form-control bg-light fw-bold rounded-4 border-2 text-kirmizi" id="secilen_hizmet" value="Hızlı Ekspres (45 Dk)" readonly></div>
                        <div class="row mb-3">
                            <div class="col-6"><label class="form-label fw-bold small text-secondary">Araç</label><select class="form-select rounded-4 py-2 border-2" id="arac" onchange="aracDegisti(); fiyatHesaplaIste();"><option value="Motor">Motor</option><option value="Araba">Araba</option></select></div>
                            <div class="col-6"><label class="form-label fw-bold small text-secondary">Ağırlık</label><select class="form-select rounded-4 py-2 border-2" id="agirlik" onchange="fiyatHesaplaIste()"></select></div>
                        </div>
                        <div class="mb-3 autocomplete-wrapper"><label class="form-label small text-muted">Çıkış Adresi</label><input type="text" class="form-control rounded-4 py-2 border-2" id="cikis_adres" required></div>
                        <div class="mb-3"><label class="form-label small text-muted">Çıkış Detay</label><textarea class="form-control rounded-4 border-2" id="cikis_detay" rows="2" required></textarea></div>
                        <div class="row mb-3">
                            <div class="col-6"><input type="text" class="form-control rounded-4 py-2 border-2" id="gonderici_isim" placeholder="Ad Soyad" required></div>
                            <div class="col-6"><input type="tel" class="form-control rounded-4 py-2 border-2" id="gonderici_tel" placeholder="Telefon" required></div>
                        </div>
                        <div class="mb-3"><input type="text" class="form-control rounded-4 py-2 border-2" id="alici_isim" placeholder="Alıcı Ad Soyad" required></div>
                        <div class="mb-3 autocomplete-wrapper"><input type="text" class="form-control rounded-4 py-2 border-2" id="alici_adres" placeholder="Alıcı Adresi" required></div>
                        <div class="mb-3"><textarea class="form-control rounded-4 border-2" id="alici_detay" rows="2" placeholder="Alıcı Detay" required></textarea></div>
                        <div class="mb-3"><input type="tel" class="form-control rounded-4 py-2 border-2" id="alici_tel" placeholder="Alıcı Telefon" required></div>
                        <div class="mb-4"><div id="harita"></div></div>
                        <div class="alert p-3 rounded-4 mb-3" style="background-color: var(--hk-kirmizi-acik);">
                            <span class="d-block small text-muted">Mesafe: <strong id="mesafeYazisi">-</strong> km</span>
                            <span class="fs-4 fw-black text-kirmizi">Tutar: <span id="tutarYazisi">0.00</span> TL</span>
                        </div>
                        <button type="submit" class="btn btn-kirmizi w-100 py-3 fw-bold rounded-4 shadow-sm">Siparişi Onayla</button>
                    </form>
                </div>
            </div>

            <div id="page-profil" class="page-content" style="display: none;">
                <h4 class="fw-bold mb-3 text-dark">Profil</h4>
                <div class="card shadow-sm p-4 border-0 rounded-5 bg-white">
                    <button type="button" onclick="cikisYap()" class="btn btn-outline-secondary w-100 rounded-4 py-2 fw-semibold">Oturumu Kapat</button>
                </div>
            </div>
        </div>
    </div>

    <div id="destekModal" class="destek-modal">
        <div class="p-3 text-white d-flex justify-content-between align-items-center bg-dark">
            <h5 class="fw-bold m-0">Canlı Destek</h5>
            <button class="btn-close btn-close-white" onclick="destekKapat()"></button>
        </div>
        <div id="destekMesajlarAlani" class="flex-grow-1 p-3 overflow-auto"></div>
        <div class="p-3 bg-white border-top">
            <form onsubmit="destekMesajGonder(event)" class="input-group">
                <input type="text" class="form-control rounded-start-4 border-2" id="destekInput" placeholder="Mesajınız..." required>
                <button class="btn btn-kirmizi fw-bold rounded-end-4 px-4" type="submit">İlet</button>
            </form>
        </div>
    </div>

    <div class="bottom-nav shadow-lg" id="bottomNav" style="display: none;">
        <button onclick="sayfaDegistir('gonderiler')" class="active" id="nav-btn-gonderiler"><span class="icon">📊</span>Panel</button>
        <button onclick="sayfaDegistir('yenigonderi')" id="nav-btn-yenigonderi"><span class="icon">🚀</span>Yeni</button>
        <button onclick="destekAc()"><span class="icon">💬</span>Destek</button>
        <button onclick="sayfaDegistir('profil')" id="nav-btn-profil"><span class="icon">⚙️</span>Profil</button>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script>
    let registeredEmail = "", currentUser = null, aktifSiparisVerileri = [];

    document.addEventListener("DOMContentLoaded", () => {
        let user = localStorage.getItem("hemenkurye_user");
        if (user) {
            currentUser = JSON.parse(user);
            document.getElementById("auth-container").style.display = "none";
            document.getElementById("app-container").style.display = "block";
            document.getElementById("bottomNav").style.display = "flex";
            aktifSiparisleriGetir();
            setInterval(aktifSiparisleriGetir, 3000);
        }
    });

    async function girisYap(e) {
        e.preventDefault();
        let email = document.getElementById("login_email").value;
        let password = document.getElementById("login_password").value;
        let res = await fetch("/api/login", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({email, password}) });
        let data = await res.json();
        if (res.ok) { localStorage.setItem("hemenkurye_user", JSON.stringify(data.user)); location.reload(); }
        else { alert(data.detail || "Hata"); }
    }

    async function kayitOl(e) {
        e.preventDefault();
        let res = await fetch("/api/register", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({
            name: document.getElementById("reg_name").value, email: document.getElementById("reg_email").value,
            phone: document.getElementById("reg_phone").value, password: document.getElementById("reg_password").value
        })});
        let data = await res.json();
        if (res.ok) {
            registeredEmail = document.getElementById("reg_email").value;
            alert(data.message);
            document.getElementById("register-form").style.display = "none";
            document.getElementById("verify-section").style.display = "block";
        } else { alert(data.detail || "Hata"); }
    }

    async function dogrulaKodu() {
        let res = await fetch("/api/verify-email", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({email: registeredEmail, otp_code: document.getElementById("otp_code_input").value}) });
        if (res.ok) { alert("Doğrulandı!"); location.reload(); } else { alert("Hatalı kod"); }
    }

    function cikisYap() { localStorage.removeItem("hemenkurye_user"); location.reload(); }

    function sayfaDegistir(sayfaAdi) {
        document.querySelectorAll(".page-content").forEach(el => el.style.display = "none");
        document.querySelectorAll(".bottom-nav button").forEach(el => el.classList.remove("active"));
        if(sayfaAdi === 'gonderiler') { document.getElementById("page-gonderiler").style.display = "block"; document.getElementById("nav-btn-gonderiler").classList.add("active"); }
        else if(sayfaAdi === 'yenigonderi') { document.getElementById("page-yenigonderi").style.display = "block"; document.getElementById("nav-btn-yenigonderi").classList.add("active"); setTimeout(() => map.invalidateSize(), 200); }
        else if(sayfaAdi === 'profil') { document.getElementById("page-profil").style.display = "block"; document.getElementById("nav-btn-profil").classList.add("active"); }
    }

    function hizmetSec(tur) { document.getElementById("secilen_hizmet").value = tur; sayfaDegistir('yenigonderi'); fiyatHesaplaIste(); }

    async function siparisGonder(e) {
        e.preventDefault();
        let payload = {
            user_email: currentUser.email, hizmet_tipi: document.getElementById("secilen_hizmet").value,
            arac: document.getElementById("arac").value, agirlik: parseInt(document.getElementById("agirlik").value),
            cikis_adres: document.getElementById("cikis_adres").value, cikis_detay: document.getElementById("cikis_detay").value,
            cikis_lat: parseFloat(document.getElementById("cikis_lat").value), cikis_lon: parseFloat(document.getElementById("cikis_lon").value),
            gonderici_isim: document.getElementById("gonderici_isim").value, gonderici_tel: document.getElementById("gonderici_tel").value,
            alici_isim: document.getElementById("alici_isim").value, alici_adres: document.getElementById("alici_adres").value,
            alici_detay: document.getElementById("alici_detay").value, alici_lat: parseFloat(document.getElementById("alici_lat").value),
            alici_lon: parseFloat(document.getElementById("alici_lon").value), alici_tel: document.getElementById("alici_tel").value
        };
        let res = await fetch("/api/siparis-olustur", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload) });
        let data = await res.json();
        if(res.ok) { alert("Sipariş Alındı! No: #" + data.siparis_id); sayfaDegistir('gonderiler'); } else { alert("Hata"); }
    }

    async function aktifSiparisleriGetir() {
        if(!currentUser) return;
        let res = await fetch("/api/siparislerim?email=" + encodeURIComponent(currentUser.email));
        let data = await res.json();
        let container = document.getElementById("aktif-siparisler-listesi");
        if(!data || data.length === 0) { container.innerHTML = '<div class="alert alert-light border rounded-4 text-center text-muted py-4">Aktif sipariş yok.</div>'; return; }
        let html = "";
        data.forEach(s => {
            html += `<div class="card border-0 shadow-sm mb-3 rounded-4 p-3 border-start border-4 border-danger">
                <div class="d-flex justify-content-between align-items-center mb-2"><span class="badge bg-dark">#${s.id}</span><span class="badge bg-warning text-dark">${s.durum}</span></div>
                <p class="mb-1 small text-secondary"><strong>Alım:</strong> ${s.cikis_adres}</p>
                <p class="mb-1 small text-secondary"><strong>Varış:</strong> ${s.alici_adres}</p>
                <div class="d-flex justify-content-between mt-2 pt-2 border-top"><span class="small text-muted">${s.hizmet_tipi}</span><span class="fw-bold text-kirmizi">${s.tutar} TL</span></div>
            </div>`;
        });
        container.innerHTML = html;
    }

    function aracDegisti() {
        let arac = document.getElementById("arac").value, agirlikSelect = document.getElementById("agirlik");
        agirlikSelect.innerHTML = "";
        let opts = arac === "Motor" ? [{d:2,m:"2 kg"}, {d:10,m:"10 kg"}, {d:20,m:"20 kg"}] : [{d:30,m:"30 kg"}, {d:100,m:"100 kg"}];
        opts.forEach(o => { let opt = document.createElement("option"); opt.value = o.d; opt.text = o.m; agirlikSelect.appendChild(opt); });
    }
    aracDegisti();

    var map = L.map('harita').setView([41.0082, 28.9784], 11);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);
    var currentMarker = null;

    function haritadaGoster(lat, lon, baslik) {
        if (currentMarker) map.removeLayer(currentMarker);
        currentMarker = L.marker([lat, lon]).addTo(map).bindPopup(baslik).openPopup();
        map.setView([lat, lon], 14);
    }

    function fiyatHesaplaIste() {
        let cLat = document.getElementById("cikis_lat").value, aLat = document.getElementById("alici_lat").value;
        if(!cLat || !aLat) return;
        fetch("/api/fiyat-hesapla", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
            cikis_lat: parseFloat(cLat), cikis_lon: parseFloat(document.getElementById("cikis_lon").value),
            alici_lat: parseFloat(aLat), alici_lon: parseFloat(document.getElementById("alici_lon").value),
            hizmet_tipi: document.getElementById("secilen_hizmet").value, arac: document.getElementById("arac").value, agirlik: parseInt(document.getElementById("agirlik").value)
        }}).then(res => res.json()).then(data => {
            document.getElementById("tutarYazisi").innerText = data.tutar;
            document.getElementById("mesafeYazisi").innerText = data.mesafe;
        });
    }

    function setupAutocomplete(input, isCikis) {
        let timeoutId;
        input.addEventListener("input", function() {
            let val = this.value;
            if (!val || val.length < 3) return;
            clearTimeout(timeoutId);
            timeoutId = setTimeout(() => {
                fetch("/api/ara?q=" + encodeURIComponent(val)).then(res => res.json()).then(data => {
                    let existing = document.querySelector(".autocomplete-items");
                    if (existing) existing.remove();
                    if (!data || data.length === 0) return;
                    let a = document.createElement("DIV"); a.setAttribute("class", "autocomplete-items"); this.parentNode.appendChild(a);
                    data.forEach(item => {
                        let b = document.createElement("DIV"); b.innerHTML = "<strong>" + item.display_name + "</strong>";
                        b.addEventListener("click", function() {
                            input.value = item.display_name; a.remove();
                            if(isCikis) { document.getElementById("cikis_lat").value = item.lat; document.getElementById("cikis_lon").value = item.lon; }
                            else { document.getElementById("alici_lat").value = item.lat; document.getElementById("alici_lon").value = item.lon; }
                            haritadaGoster(parseFloat(item.lat), parseFloat(item.lon), item.display_name);
                            fiyatHesaplaIste();
                        });
                        a.appendChild(b);
                    });
                });
            }, 300);
        });
    }
    setupAutocomplete(document.getElementById("cikis_adres"), true);
    setupAutocomplete(document.getElementById("alici_adres"), false);

    function destekAc() { document.getElementById("destekModal").style.display = "flex"; destekMesajlariYukle(); }
    function destekKapat() { document.getElementById("destekModal").style.display = "none"; }
    async function destekMesajlariYukle() {
        let res = await fetch("/api/destek-mesajlari?email=" + encodeURIComponent(currentUser.email));
        let data = await res.json();
        let alan = document.getElementById("destekMesajlarAlani");
        let html = "";
        data.forEach(m => {
            html += `<div class="card p-2 border-0 shadow-sm mb-2 rounded-4 ${m.gonderen === 'Kullanıcı' ? 'ms-auto bg-danger text-white' : 'bg-white text-dark'}" style="max-width:85%;"><small style="font-size:10px;" class="opacity-75">${m.gonderen}</small><p class="mb-0 small mt-1">${m.mesaj}</p></div>`;
        });
        alan.innerHTML = html;
        alan.scrollTop = alan.scrollHeight;
    }
    async function destekMesajGonder(e) {
        e.preventDefault();
        let input = document.getElementById("destekInput");
        await fetch("/api/destek-mesaj-gonder", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({ user_email: currentUser.email, gonderen: "Kullanıcı", mesaj: input.value }) });
        input.value = ""; destekMesajlariYukle();
    }
    </script>
</body>
</html>"""

# Render doğrudan "main:app" ile çalıştırır.
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), reload=True)