# app/model.py
from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()

class Job(Base):
    """
    Model for storing job openings at your company.
    """
    __tablename__ = "jobs"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True, nullable=False)
    mode = Column(String, nullable=False)
    location = Column(String, default="Remote")
    description = Column(Text, nullable=True)
    is_active = Column(Integer, default=1) # 1 for active, 0 for inactive

class User(Base):
    """
    Model for ALL users of the system.
    This includes candidates, HR staff, and admins.
    The 'role' field distinguishes their permissions and type.
    """
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    # Password is required for all users to log in (candidates included)
    hashed_password = Column(String, nullable=False)
    # Role distinguishes user type: 'candidate', 'hr', 'admin'
    role = Column(String, nullable=False) 

    # --- Fields for candidates ---
    phone_number = Column(String, nullable=True)
    

class Application(Base):
    """
    Model to link a User (acting as a candidate) to a Job.
    """
    __tablename__ = "applications"
    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False)
    # This now links to the User table
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Store answers from the form
    salary_expectation = Column(String, nullable=True)
    skills = Column(Text, nullable=False)
    resume_filename = Column(String, nullable=True)  
    
    # Tracking fields
    application_date = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String, default="Pending Payment", nullable=False) # "Pending Payment", "Completed"
    
    # Field to link to the Stripe transaction
    payment_intent_id = Column(String, unique=True, nullable=True)
