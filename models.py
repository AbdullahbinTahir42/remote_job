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

    applications = relationship("Application", back_populates="job", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False)
    phone_number = Column(String, nullable=True)
    resume_filename = Column(String, nullable=True)
    profile_status = Column(String, default="No", nullable=False)  # ✅ New column


    profile = relationship("Profile", back_populates="user", uselist=False, cascade="all, delete-orphan")
    applications = relationship("Application", back_populates="user", cascade="all, delete-orphan")


class Profile(Base):
    __tablename__ = "profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    job_title = Column(String, nullable=False)
    resume_filename = Column(String, nullable=True)
    salary_expectation = Column(String, nullable=True)
    skills = Column(Text, nullable=True)  # comma-separated
    remote_type = Column(Text, nullable=True)
    location = Column(String, nullable=True)
    benefits = Column(Text, nullable=True)
    career_level = Column(String, nullable=True)
    work_type = Column(String, nullable=True)

    application_date = Column(DateTime(timezone=True), server_default=func.now())
    payment_status = Column(String, default="Pending", nullable=False)

    user = relationship("User", back_populates="profile")


class Application(Base):
    __tablename__ = "applications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False)

    user = relationship("User", back_populates="applications")
    job = relationship("Job", back_populates="applications")
