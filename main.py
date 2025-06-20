import os
import json
import io
from datetime import timedelta
from typing import List

# --- Third-party libraries ---
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from sqlalchemy import create_engine,or_

# --- File parsing libraries ---
import pdfplumber
import docx
from bs4 import BeautifulSoup
from striprtf.striprtf import rtf_to_text

# --- Google Gemini AI ---
import google.generativeai as genai

# --- Project-specific imports ---
# These import from your other project files: 
# auth.py, database.py, models.py, schemas.py
import models
from models import User, Job
from schemas import UserCreate, UserSchema, Token, JobCreate, JobSchema, JobSearchSchema
from auth import get_password_hash, verify_password, create_access_token, oauth2_scheme, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from database import SessionLocal, engine

# --- Initial Setup ---
load_dotenv()

# Create all database tables based on your models
models.Base.metadata.create_all(bind=engine)

# Configure the Gemini AI client
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost", "http://localhost:3000"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
try: genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
except Exception as e: print(f"Error configuring Gemini API: {e}")

# --- Dependencies ---
def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def get_user(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

async def get_current_active_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(db, email=email)
    if user is None or not user.is_active: raise credentials_exception
    return user

async def get_current_admin_user(current_user: User = Depends(get_current_active_user)):
    """New dependency to ensure the user is an admin."""
    if not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges")
    return current_user

# --- Helper Functions (Text Extraction & AI Analysis) ---
def extract_text_from_file(file: UploadFile) -> str:
    filename = file.filename
    content = file.file.read()
    text = ""
    try:
        if filename.endswith(".pdf"): text = "".join([(p.extract_text() or "") + "\n" for p in pdfplumber.open(io.BytesIO(content)).pages])
        elif filename.endswith(".docx"): text = "\n".join([p.text for p in docx.Document(io.BytesIO(content)).paragraphs])
        elif filename.endswith(".html"): text = BeautifulSoup(content, "html.parser").get_text(separator="\n")
        elif filename.endswith(".rtf"): text = rtf_to_text(content.decode('utf-8', errors='ignore'))
        elif filename.endswith(".txt"): text = content.decode('utf-8', errors='ignore')
        else: raise HTTPException(status_code=400, detail=f"Unsupported file type: {filename}")
        return text
    except Exception as e: raise HTTPException(status_code=500, detail=f"Could not process file {filename}: {e}")

async def analyze_resume_with_gemini(resume_text: str) -> dict:
    """
    Uses Google Gemini to extract structured JSON information from resume text.
    This is the corrected and integrated version of your function.
    """
    if not resume_text:
        return {}

    # Initialize the Gemini model
    model = genai.GenerativeModel('gemini-1.5-flash-latest')

    # Define the generation configuration to enforce JSON output
    # This is the most reliable way to get a clean JSON response.
    generation_config = genai.types.GenerationConfig(
        response_mime_type="application/json"
    )

    # The prompt now correctly includes the resume_text variable
    prompt = (
        "Analyze the following resume text. Your task is to extract two specific pieces of information "
        "and return them as a single, valid JSON object. Do not include any text, notes, or formatting "
        "outside of the final JSON structure.\n\n"
        "1.  **Detect Role**: Identify the candidate's primary professional role. Classify it as one of the following: "
        "'Frontend Developer', 'Backend Developer', 'Full Stack Developer', 'Data Scientist', 'UI/UX Designer', "
        "'Product Manager', or a similar concise professional title based on their core skills.\n\n"
        "2.  **Detect Location**: Extract the city and country from the candidate's contact information. If no location is found, return null.\n\n"
        "The JSON object MUST have exactly these two keys:\n"
        "{\n"
        "  \"detectedRole\": \"[The role you identified]\",\n"
        "  \"detectedLocation\": \"[The location you extracted, e.g., 'San Francisco, USA']\"\n"
        "}\n\n"
        # The resume_text is now correctly passed into the prompt
        f"--- RESUME TEXT ---\n{resume_text}"
    )

    try:
        # Use generate_content_async for non-blocking call in an async context like FastAPI
        response = await model.generate_content_async(
            prompt,
            generation_config=generation_config
        )
        # The model now returns a clean JSON string directly, no manual cleaning needed.
        return json.loads(response.text)
    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        # Return a dictionary with an error key for robust error handling
        return {"error": f"Failed to analyze resume with AI: {e}"}

# --- API Endpoints ---
@app.post("/register/", response_model=UserSchema, tags=["Authentication"])
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    if get_user(db, email=user.email): raise HTTPException(status_code=400, detail="Email already registered")
    db_user = User(email=user.email, hashed_password=get_password_hash(user.password))
    db.add(db_user); db.commit(); db.refresh(db_user)
    return db_user

@app.post("/token", response_model=Token, tags=["Authentication"])
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = get_user(db, email=form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    token = create_access_token(data={"sub": user.email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": token, "token_type": "bearer"}

@app.get("/users/me/", response_model=UserSchema, tags=["Users"])
async def read_current_user(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.post("/resume/analyze/", tags=["Resume"])
async def analyze_resume(resume: UploadFile = File(...), current_user: User = Depends(get_current_active_user)):
    resume_text = extract_text_from_file(resume)
    if not resume_text: raise HTTPException(status_code=400, detail="Could not extract text from file.")
    analysis = await analyze_resume_with_gemini(resume_text)
    if "error" in analysis: raise HTTPException(status_code=500, detail=analysis["error"])
    return JSONResponse(content={"message": "Resume analyzed successfully.", "analysis": analysis})

@app.post("/jobs/", response_model=JobSchema, tags=["Jobs (Admin)"])
def create_job(job: JobCreate, db: Session = Depends(get_db), admin_user: User = Depends(get_current_admin_user)):
    """Creates a new job posting. Requires admin privileges."""
    db_job = Job(**job.model_dump())
    db.add(db_job); db.commit(); db.refresh(db_job)
    return db_job

@app.get("/users/me/preferences/", response_model=JobSearchSchema, tags=["Users"])
def get_user_preferences(current_user: models.User = Depends(get_current_active_user)):
    """
    NEW: Fetches the current logged-in user's saved search preferences.
    The frontend will call this when the search page loads.
    """
    # current_user.preferences is available because of the relationship we added in models.py
    if not current_user.preferences:
        # If the user has never searched before, return empty default values
        return JobSearchSchema()
    return current_user.preferences


# --- Replace your existing search_jobs function with this updated version ---
@app.post("/jobs/search/", response_model=List[JobSchema], tags=["Jobs"])
def search_jobs(
    search: JobSearchSchema, 
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(get_current_active_user)
):
    """
    UPDATED: First, it saves the user's complete preference list.
    Then, it searches for jobs using only the main 3 criteria.
    """
    
    # --- Step 1: Save/Update User Preferences ---
    preference = db.query(models.UserPreference).filter(models.UserPreference.user_id == current_user.id).first()
    
    if preference:
        # If preferences already exist for this user, update them
        preference.skills = search.skills
        preference.location = search.location
        preference.seniority_level = search.seniority_level
        preference.salary = search.salary
        preference.mode = search.mode
    else:
        # If no preferences exist, create a new record
        preference = models.UserPreference(**search.model_dump(), user_id=current_user.id)
        db.add(preference)
        
    db.commit() # Save the changes to the database

    # --- Step 2: Perform the Search with Main 3 Criteria ONLY ---
    query = db.query(models.Job)

    # We use the same 'search' object, but only for the important filters
    if search.location:
        query = query.filter(models.Job.location.ilike(f"%{search.location}%"))
        
    if search.seniority_level:
        query = query.filter(models.Job.seniority_level.ilike(f"%{search.seniority_level}%"))
        
    if search.skills:
        skill_filters = [or_(
            models.Job.title.ilike(f"%{skill}%"), 
            models.Job.description.ilike(f"%{skill}%")
        ) for skill in search.skills]
        query = query.filter(or_(*skill_filters))
    
    return query.all()