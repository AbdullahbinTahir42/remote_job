from pydantic import BaseModel
from typing import Optional,List


class UserCreate(BaseModel):
    email: str
    password: str

class UserSchema(BaseModel):
    id: int
    email: str
    is_active: bool
    is_admin: bool
    class Config: from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class JobBase(BaseModel):
    title: str
    company: str
    location: str
    description: str
    apply_link: str
    mode: str
    salary: Optional[str] = None
    seniority_level: str

class JobCreate(JobBase):
    pass

class JobSchema(JobBase):
    id: int
    class Config: from_attributes = True

class JobSearchSchema(BaseModel):
    """UPDATED: This schema now accepts all the user's preferences from the frontend."""
    skills: List[str] = []
    location: Optional[str] = None
    seniority_level: Optional[str] = None
    salary: Optional[str] = None
    mode: Optional[str] = None