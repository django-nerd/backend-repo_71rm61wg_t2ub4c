import os
import io
import hashlib
import secrets
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents
from schemas import Donation, Contact, Patient, Fileshistory, User

import requests

app = FastAPI(title="Charity App API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Auth helpers ---

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def hash_password(password: str) -> str:
    # Simple hash with salt for demo only. Use bcrypt in production.
    salt = os.getenv("AUTH_SALT", "static_salt")
    return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class MeResponse(BaseModel):
    email: EmailStr
    role: str
    name: str


class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str = "Salesperson"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


# In-memory token store for demo (short-lived). In production, JWT.
TOKENS = {}


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    data = TOKENS.get(token)
    if not data:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    docs = get_documents("user", {"email": data["email"]}, limit=1)
    if not docs:
        raise HTTPException(status_code=401, detail="User not found")
    doc = docs[0]
    return User(
        name=doc.get("name", ""),
        email=doc.get("email"),
        password_hash=doc.get("password_hash", ""),
        role=doc.get("role", "Salesperson"),
        is_active=doc.get("is_active", True),
    )


# --- Basic routes ---

@app.get("/")
def root():
    return {"ok": True, "service": "Charity Backend"}


@app.get("/test")
def test_database():
    info = {
        "backend": "running",
        "database": "connected" if db is not None else "not-configured",
        "collections": [],
    }
    try:
        if db is not None:
            info["collections"] = db.list_collection_names()
    except Exception as e:
        info["database"] = f"error: {str(e)}"
    return info


# --- Auth endpoints (JSON bodies to avoid multipart dependency) ---

@app.post("/auth/register")
def register(payload: RegisterRequest):
    existing = get_documents("user", {"email": str(payload.email)}, limit=1)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(name=payload.name, email=payload.email, password_hash=hash_password(payload.password), role=payload.role, is_active=True)
    create_document("user", user)
    return {"ok": True}


@app.post("/auth/login", response_model=Token)
def login(payload: LoginRequest):
    docs = get_documents("user", {"email": str(payload.email)}, limit=1)
    if not docs:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    doc = docs[0]
    if hash_password(payload.password) != doc.get("password_hash"):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = secrets.token_urlsafe(32)
    TOKENS[token] = {"email": doc.get("email"), "role": doc.get("role")}
    return Token(access_token=token)


@app.get("/auth/me", response_model=MeResponse)
def me(user: User = Depends(get_current_user)):
    return MeResponse(email=user.email, role=user.role, name=user.name)


# --- Contact form ---

@app.post("/contact")
def submit_contact(payload: Contact):
    create_document("contact", payload)
    return {"ok": True}


# --- Donations ---

@app.post("/donations/initiate")
def initiate_donation(payload: Donation):
    donation_id = create_document("donation", payload)
    return {"ok": True, "donation_id": donation_id}


@app.post("/webhooks/stripe")
def stripe_webhook(event: dict):
    event_type = event.get("type")
    if event_type == "payment_intent.succeeded":
        intent = event.get("data", {}).get("object", {})
        doc = {
            "name": intent.get("metadata", {}).get("name"),
            "email": intent.get("receipt_email"),
            "phone": intent.get("metadata", {}).get("phone"),
            "amount": float(intent.get("amount", 0)) / 100.0,
            "currency": intent.get("currency", "usd").upper(),
            "transaction_id": intent.get("id"),
            "country": intent.get("charges", {}).get("data", [{}])[0].get("billing_details", {}).get("address", {}).get("country"),
            "method": "stripe",
            "status": "success",
        }
        create_document("donation", doc)
    return {"received": True}


@app.post("/webhooks/razorpay")
def razorpay_webhook(event: dict):
    payload = event.get("payload", {})
    payment = payload.get("payment", {}).get("entity", {})
    if payment:
        doc = {
            "name": payment.get("notes", {}).get("name"),
            "email": payment.get("email"),
            "phone": payment.get("contact"),
            "amount": float(payment.get("amount", 0)) / 100.0,
            "currency": payment.get("currency", "INR").upper(),
            "transaction_id": payment.get("id"),
            "country": "IN",
            "method": payment.get("method", "upi"),
            "status": "success" if payment.get("status") == "captured" else payment.get("status", "failed"),
        }
        create_document("donation", doc)
    return {"received": True}


@app.get("/donations")
def list_donations(limit: int = 50):
    docs = get_documents("donation", {}, limit=limit)
    for d in docs:
        d["_id"] = str(d["_id"]) if "_id" in d else None
    return {"items": docs}


# --- Email sending ---
class EmailRequest(BaseModel):
    to: EmailStr
    subject: str
    html: str


@app.post("/send-email")
def send_email(req: EmailRequest):
    create_document("email", {"to": str(req.to), "subject": req.subject, "html": req.html})
    return {"ok": True}


# --- WhatsApp sending ---
class WhatsAppRequest(BaseModel):
    phone: str
    message: str


@app.post("/send-whatsapp")
def send_whatsapp(req: WhatsAppRequest):
    token = os.getenv("WHATSAPP_TOKEN")
    phone_id = os.getenv("WHATSAPP_PHONE_ID")
    if token and phone_id:
        try:
            url = f"https://graph.facebook.com/v17.0/{phone_id}/messages"
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            data = {"messaging_product": "whatsapp", "to": req.phone, "type": "text", "text": {"body": req.message}}
            requests.post(url, headers=headers, json=data, timeout=6)
        except Exception:
            pass
    create_document("whatsapp", {"phone": req.phone, "message": req.message})
    return {"ok": True}


# --- File upload + send to patient ---
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR, exist_ok=True)


@app.post("/files/upload")
def upload_file(file: UploadFile = File(...)):
    filename = f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{file.filename}"
    path = os.path.join(UPLOAD_DIR, filename)
    with open(path, "wb") as f:
        f.write(file.file.read())
    return {"ok": True, "file_name": filename, "file_path": path}


class SendFileForm(BaseModel):
    patient_name: str
    phone: Optional[str] = None
    email: Optional[EmailStr] = None
    file_name: str
    via: str  # email or whatsapp
    message: Optional[str] = None


@app.post("/files/send")
def send_file(form: SendFileForm):
    record = {
        "patient_name": form.patient_name,
        "patient_email": str(form.email) if form.email else None,
        "patient_phone": form.phone,
        "file_name": form.file_name,
        "file_path": os.path.join(UPLOAD_DIR, form.file_name),
        "sent_via": form.via,
        "status": "sent",
    }
    create_document("fileshistory", record)
    if form.phone or form.email:
        existing = get_documents("patient", {"$or": [{"phone": form.phone}, {"email": str(form.email) if form.email else None}]}, limit=1)
        if not existing:
            create_document("patient", {"name": form.patient_name, "phone": form.phone, "email": str(form.email) if form.email else None})
    return {"ok": True}


@app.get("/files/history")
def files_history(q: Optional[str] = None, limit: int = 100):
    filt = {}
    if q:
        filt = {"$or": [{"patient_phone": q}, {"patient_email": q}]}
    docs = get_documents("fileshistory", filt, limit=limit)
    for d in docs:
        d["_id"] = str(d["_id"]) if "_id" in d else None
    return {"items": docs}


@app.get("/patients")
def list_patients(limit: int = 100, phone: Optional[str] = None):
    filt = {"phone": phone} if phone else {}
    docs = get_documents("patient", filt, limit=limit)
    for d in docs:
        d["_id"] = str(d["_id"]) if "_id" in d else None
    return {"items": docs}
