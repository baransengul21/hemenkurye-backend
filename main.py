import os
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from supabase import create_client, Client
import random

app = FastAPI()

# Supabase bağlantı bilgileri
SUPABASE_URL = os.environ.get("SUPABASE_URL", "SENIN_SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "SENIN_SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Modeller
class RegisterModel(BaseModel):
    name: str
    email: EmailStr
    phone: str
    password: str

class VerifyEmailModel(BaseModel):
    email: EmailStr
    otp_code: str

class LoginModel(BaseModel):
    email: EmailStr
    password: str

class OrderCreate(BaseModel):
    pickup_address: str
    dropoff_address: str
    price: float

@app.get("/")
def read_root():
    return {"message": "HemenKurye Backend Aktif ve Çalışıyor! 🚀"}

@app.post("/api/register")
async def register(user: RegisterModel):
    try:
        # Supabase Auth ile kayıt ol
        auth_response = supabase.auth.sign_up({
            "email": user.email,
            "password": user.password,
            "options": {
                "data": {
                    "name": user.name,
                    "phone": user.phone
                }
            }
        })
        
        if not auth_response.user:
            raise HTTPException(status_code=400, detail="Kayıt oluşturulamadı!")
            
        return {"success": True, "message": "Kayıt başarılı! Lütfen e-postanızı doğrulayın."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/verify-email")
async def verify_email(data: VerifyEmailModel):
    # Şimdilik simüle edilmiş doğrulama adımı
    return {"success": True, "message": "E-posta başarıyla doğrulandı!"}

@app.post("/api/login")
async def login(credentials: LoginModel):
    try:
        auth_response = supabase.auth.sign_in_with_password({
            "email": credentials.email,
            "password": credentials.password
        })
        
        if not auth_response.session:
            raise HTTPException(status_code=400, detail="Giriş başarısız, bilgileri kontrol edin.")
            
        return {
            "success": True,
            "message": "Giriş başarılı",
            "access_token": auth_response.session.access_token,
            "user": auth_response.user
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/create-order")
async def create_order(order: OrderCreate):
    try:
        # Supabase'e siparişi kaydediyoruz
        response = supabase.table("orders").insert({
            "pickup_address": order.pickup_address,
            "dropoff_address": order.dropoff_address,
            "price": order.price,
            "status": "beklemede"
        }).execute()
        
        return {"success": True, "message": "Sipariş başarıyla oluşturuldu", "order": response.data}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))