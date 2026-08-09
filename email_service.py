import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# .env dosyasındaki gizli bilgileri yüklüyoruz
load_dotenv()

SENDER_EMAIL = os.getenv("EMAIL_USER", "Hemenkuryehk@gmail.com")
SENDER_PASSWORD = os.getenv("EMAIL_PASSWORD")

def send_otp_email(to_email: str, otp_code: str) -> bool:
    try:
        smtp_server = "smtp.gmail.com"
        smtp_port = 587

        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = "HemenKurye - E-posta Doğrulama Kodu"

        body = f"""
        Merhaba,
        
        HemenKurye platformuna hoş geldiniz! Hesabınızı doğrulamak için gereken 6 haneli aktivasyon kodunuz:
        
        {otp_code}
        
        Bu kodu uygulamaya girerek üyeliğinizi tamamlayabilirsiniz.
        
        HemenKurye Ekibi
        """
        msg.attach(MIMEText(body, 'plain', 'utf-8'))

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        server.quit()
        print(f"✅ OTP maili başarıyla gönderildi: {to_email}")
        return True
    except Exception as e:
        print(f"❌ E-posta Gönderme Hatası: {e}")
        return False