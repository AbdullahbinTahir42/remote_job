# app/schemas.py
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
    """Base schema for user data."""
    email: EmailStr
    full_name: str
    phone_number: Optional[str] = None

class UserCreate(UserBase):
    """Schema for creating a new user (registration)."""
    password: str

class UserLogin(BaseModel):
    """Schema for user login."""
    email: EmailStr
    password: str

class User(UserBase):
    """
    Schema for returning user data to the client.
    Crucially, it does NOT include the password.
    """
    id: int
    role: str
    resume_filename: Optional[str] = None

    class Config:
        from_attributes = True


# --- Job Schemas ---
class JobBase(BaseModel):
    """Base schema for job data."""
    title: str
    mode: str
    location: str
    description: Optional[str] = None

class JobCreate(JobBase):
    """Schema for creating a new job posting (admin)."""
    pass

class Job(JobBase):
    """Schema for returning job data to the client."""
    id: int
    is_active: int

    class Config:
        from_attributes = True


class ApplicationCreate(BaseModel):
    """
    UPDATED: This is the schema for the JSON data your frontend will send
    when a user submits their job application preferences.
    """
    job_title: str  # User provides the title of the job they want
    location: str
    skills: str     # This field is required as per your database model
    salary_expectation: Optional[str] = None
    seniority_level: Optional[str] = None  # e.g., "Entry-level", "Mid-level", "Senior"
    job_type: Optional[str] = None         # e.g., "Full-time", "Part-time", "Contract"
    benefits: Optional[List[str]] = []     # A list of desired benefits

class Application(ApplicationCreate):
    """
    UPDATED: This schema represents the final application record that is
    returned by the API after it has been saved to the database.
    It now includes all fields from the creation process plus system-generated fields.
    """
    id: int
    job_id: int
    user_id: int
    application_date: datetime
    status: str
    # ADDED: This field will hold the filename of the resume
    resume_filename: Optional[str] = None 

    class Config:
        from_attributes = True
