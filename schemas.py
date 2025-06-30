from pydantic import BaseModel, EmailStr
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


class User(UserBase):
    """Schema for returning user data (excluding password)."""
    id: int
    role: str
    resume_filename: Optional[str] = None  # Can be removed if not used anymore

    class Config:
        from_attributes = True


# --- Job Schemas ---
class JobBase(BaseModel):
    """Shared fields used in job-related schemas."""
    title: str
    mode: str
    location: str
    description: Optional[str] = None


class JobCreate(JobBase):
    """Schema for creating a new job posting."""
    pass


class Job(JobBase):
    """Schema for returning job data."""
    id: int
    is_active: int

    class Config:
        from_attributes = True


# --- Application Schemas ---
class ApplicationCreate(BaseModel):
    job_title: str
    salary_expectation: Optional[str] = None
    skills: List[str]  # Changed to list to match multiple skills selected
    categories: Optional[List[str]] = None  # For job categories (e.g., full-time, part-time)
    location: Optional[str] = None
    benefits: Optional[List[str]] = None
    career_level: Optional[str] = None
    work_type: Optional[str] = None  # e.g., full-time, freelance
    # Add any other fields you collect in your frontend form here

class Application(BaseModel):
    id: int
    job_id: int
    user_id: int
    salary_expectation: Optional[str]
    skills: List[str]
    categories: Optional[List[str]] = None
    location: Optional[str] = None
    benefits: Optional[List[str]] = None
    career_level: Optional[str] = None
    work_type: Optional[str] = None
    resume_filename: Optional[str]
    application_date: datetime
    status: str
    payment_intent_id: Optional[str]

    class Config:
        from_attributes = True
    

