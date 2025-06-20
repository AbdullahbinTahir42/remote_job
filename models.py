from sqlalchemy import Column, Integer, String, Text, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.sqlite import JSON as SQLiteJSON
from sqlalchemy.orm import relationship


Base = declarative_base()

class Job(Base):
    __tablename__ = "jobs"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    company = Column(String, index=True)
    location = Column(String)
    description = Column(Text)
    apply_link = Column(String)
    mode = Column(String) # 'Full-time', 'Part-time', etc.
    salary = Column(String, nullable=True)
    seniority_level = Column(String) # 'Entry-Level', 'Senior', etc.

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    
    # This line creates the link to the new UserPreference table
    preferences = relationship("UserPreference", back_populates="user", uselist=False, cascade="all, delete-orphan")


# --- Add this new model to the same file ---
class UserPreference(Base):
    """This new table will store the last search preferences for a user."""
    __tablename__ = "user_preferences"
    
    id = Column(Integer, primary_key=True, index=True)
    # This creates a one-to-one link with the users table
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    
    # These columns will store all the preferences from the frontend
    skills = Column(SQLiteJSON, default=[])
    location = Column(String, nullable=True)
    seniority_level = Column(String, nullable=True)
    salary = Column(String, nullable=True)
    mode = Column(String, nullable=True) # e.g., 'Full-time'
    
    user = relationship("User", back_populates="preferences")

