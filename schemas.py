"""
Database Schemas for Charity App

Each Pydantic model name maps to a MongoDB collection using the lowercase
class name (e.g., Donation -> "donation").

Collections required:
- donations
- contacts
- patients
- filesHistory
- users (for authentication/roles)
"""
from typing import Optional, Literal, List
from pydantic import BaseModel, Field, EmailStr

# Users (Authentication + Roles)
class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email address")
    password_hash: str = Field(..., description="BCrypt password hash")
    role: Literal["Admin", "Manager", "Salesperson"] = Field("Salesperson", description="Role-based access")
    is_active: bool = Field(True)

# Contact form submissions
class Contact(BaseModel):
    name: str
    email: EmailStr
    phone: Optional[str] = None
    message: str

# Patients contacted by the team
class Patient(BaseModel):
    name: str
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    notes: Optional[str] = None

# History of files sent to patients
class Fileshistory(BaseModel):
    patient_name: str
    patient_email: Optional[EmailStr] = None
    patient_phone: Optional[str] = None
    file_name: str
    file_path: Optional[str] = None
    sent_via: Literal["email", "whatsapp"]
    status: Literal["queued", "sent", "failed"] = "sent"
    error: Optional[str] = None

# Donations
class Donation(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    amount: float = Field(..., gt=0)
    currency: Literal["INR", "USD", "EUR", "GBP"] = "INR"
    transaction_id: Optional[str] = None
    country: Optional[str] = None
    method: Optional[Literal["upi", "netbanking", "card", "stripe"]] = None
    status: Literal["initiated", "success", "failed"] = "initiated"
    receipt_url: Optional[str] = None

# Optional: Simple testimonial model if needed for future
class Testimonial(BaseModel):
    name: str
    story: str
    source: Optional[str] = Field(None, description="Instagram/Facebook link")
    amount_raised: Optional[float] = None
