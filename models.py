from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class Job(Base):
    __tablename__ = "jobs"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True, nullable=False)
    mode = Column(String, nullable=False)
    location = Column(String, default="Remote")
    description = Column(Text, nullable=True)
    is_active = Column(Integer, default=1)

    # ✅ Add this:
    applications = relationship("Application", back_populates="job", cascade="all, delete-orphan")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False)

    phone_number = Column(String, nullable=True)

    # ✅ New: Store resume filename
    resume_filename = Column(String, nullable=True)

    # ✅ Applications relationship
    applications = relationship("Application", back_populates="user", cascade="all, delete-orphan")


class Application(Base):
    __tablename__ = "applications"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    salary_expectation = Column(String, nullable=True)
    skills = Column(Text, nullable=False)
    application_date = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String, default="Pending Payment", nullable=False)
    payment_intent_id = Column(String, unique=True, nullable=True)

    job = relationship("Job", back_populates="applications")
    user = relationship("User", back_populates="applications")
