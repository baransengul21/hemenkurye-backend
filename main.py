import random
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from supabase import create_client, Client
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = FastAPI()

# Supabase URL ve Service Role (Gizli) Anahtar
SUPABASE_URL = "https://ocowoukrscglyjcmbmaw.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9jb3dvdWtyc2NnbHlqY21ibWF3Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4NjI2MjczMCwiZXhwIjoyMTAxODM4NzMwfQ.EHI3ISE7vKsXFUsi7wvtaS-ZGimQ95IfbcgYo9Yv4UM"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# E-posta Bilgileri
EMAIL_USER = "Hemenkuryehk@gmail.com"
EMAIL_PASSWORD = "leupyscwkjgvsvtj"

# Geçici Kod Deposu (Bellekte tutulur)
otp_storage = {}

class RegisterRequest(BaseModel):
    name: str
    email: str
    phone: str
    password: str

class VerifyRequest(BaseModel):
    email: str
    otp_code: str

class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/api/register")
def register(user: RegisterRequest):
    try:
        data = {
            "full_name": user.name,
            "email": user.email,
            "phone": user.phone,
            "password": user.password, # Şifreyi de kaydediyoruz
            "is_verified": False
        }
        response = supabase.table("profiles").insert(data).execute()
    except Exception as e:
        print("--- SUPABASE HATASI ---", str(e))
        raise HTTPException(status_code=400, detail=f"Veritabanı hatası: {str(e)}")

    code = str(random.randint(100000, 999999))
    otp_storage[user.email] = code

    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_USER
        msg["To"] = user.email
        msg["Subject"] = "HemenKurye Doğrulama Kodu"

        body = f"Merhaba {user.name},\n\nHemenKurye kayıt doğrulama kodunuz: {code}"
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_USER, user.email, msg.as_string())
        server.quit()
    except Exception as e:
        print("--- MAİL GÖNDERME HATASI ---", str(e))
        raise HTTPException(status_code=500, detail=f"E-posta gönderilemedi: {str(e)}")

    return {"message": "Kayıt başarılı, doğrulama kodu gönderildi."}

@app.post("/api/verify-email")
def verify_code(data: VerifyRequest):
    stored_code = otp_storage.get(data.email)
    
    if not stored_code or stored_code != data.otp_code:
        raise HTTPException(status_code=400, detail="Geçersiz veya süresi dolmuş kod.")
    
    try:
        supabase.table("profiles").update({"is_verified": True}).eq("email", data.email).execute()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Güncelleme hatası: {str(e)}")
        
    del otp_storage[data.email]
    
    return {"message": "Hesap başarıyla doğrulandı!"}

@app.post("/api/login")
def login(user: LoginRequest):
    try:
        # Kullanıcıyı e-posta ile veritabanında arıyoruz
        response = supabase.table("profiles").select("*").eq("email", user.email).execute()
        users = response.data

        if not users:
            raise HTTPException(status_code=400, detail="Bu e-posta ile kayıtlı kullanıcı bulunamadı.")

        db_user = users[0]

        # Şifre kontrolü
        if db_user.get("password") != user.password:
            raise HTTPException(status_code=400, detail="Hatalı şifre!")

        # Hesap doğrulanmış mı kontrolü
        if not db_user.get("is_verified", False):
            raise HTTPException(status_code=400, detail="Lütfen önce hesabınızı e-posta kodu ile doğrulayın.")

        return {"message": "Giriş başarılı!", "user": db_user}

    except HTTPException as he:
        raise he
    except Exception as e:
        print("--- GİRİŞ HATASI ---", str(e))
        raise HTTPException(status_code=400, detail=f"Giriş hatası: {str(e)}")