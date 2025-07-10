from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional, List
from datetime import datetime

# --- Token Schemas for Authentication ---
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None


# --- User Schemas ---
class UserBase(BaseModel):
    """Shared fields used in user-related schemas."""
    email: EmailStr
    full_name: str
    phone_number: Optional[str] = None


class UserCreate(UserBase):
    """Schema for user registration."""
    password: str


class UserLogin(BaseModel):
    """Schema for user login."""
    email: EmailStr
    password: str


class S_User(UserBase):
    id: int
    role: str
    resume_filename: Optional[str] = None
    profile_id: Optional[int] = None
    payment_status: Optional[str] = None

    class Config:
        from_attributes = True


# --- Job Schemas ---
class JobBase(BaseModel):
    """Shared fields used in job-related schemas."""
    title: str
    location: str
    type: str  # Full-time, Part-time, etc.
    experience: str  # Entry, Mid, Senior, etc.
    salary: Optional[str] = None
    company: str
    description: Optional[str] = None


class JobCreate(JobBase):
    """Schema for creating a new job posting."""
    pass


class S_Job(JobBase):
    """Schema for returning job data."""
    id: int
    is_active: int
    posted_at: datetime

    class Config:
        from_attributes = True


class Salary(BaseModel):
    amount: float
    type: str




# --- Application Schemas ---
class NewProfile(BaseModel):
    job_title: str
    salary_expectation: Optional[Salary] = None
    skills: List[str]  # Changed to list to match multiple skills selected
    remote_type: Optional[str] = None  # For job categories (e.g., full-time, part-time)
    location: Optional[str] = None
    benefits: Optional[List[str]] = None
    career_level: Optional[str] = None
    work_type: Optional[str] = None  # e.g., full-time, freelance
    # Add any other fields you collect in your frontend form here

class CreateProfile(BaseModel):
    id: int
    user_id: int
    full_name:str
    email: EmailStr
    job_title:str
    salary_expectation: Optional[str]
    skills: List[str]
    remote_type: Optional[str] = None
    location: Optional[str] = None
    benefits: Optional[List[str]] = None
    career_level: Optional[str] = None
    work_type: Optional[str] = None
    resume_filename: Optional[str]
    profile_date: datetime
    payment_status: str
    

    class Config:
        from_attributes = True

    @field_validator("skills", "benefits", mode='before')
    @classmethod
    def split_str(cls, v):
        if v is None:
            return v
        if isinstance(v, str):
            # Split the string by comma, and remove any leading/trailing whitespace from each item
            return [item.strip() for item in v.split(',')]
        return v
    

class ApplicationBase(BaseModel):
    job_id: int
    cover_letter: Optional[str] = None


# --- Create Schema (for POST requests) ---
class ApplicationCreate(ApplicationBase):
    pass


# --- Read Schema (for GET responses) ---
class S_Application(ApplicationBase):
    id: int
    user_id: int
    application_date: datetime
    status: str

    class Config:
        from_attributes = True

class ApplicationOut(BaseModel):
    id: int
    user_email: str
    full_name: str
    job_title: str
    status: str
    application_date: datetime
    cover_letter: Optional[str]

    class Config:
        from_attributes = True


class PaymentRequest(BaseModel):
    profile_id: int


class PaymentCreate(BaseModel):
    name: str
    email: str
    plan: str
    method: str
    terms_accepted: bool

    class Config:
        from_attributes = True