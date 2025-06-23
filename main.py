import os
import json
import io
from datetime import timedelta
from typing import List




# --- Third-party libraries ---
import shutil
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form,UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from sqlalchemy import or_, func

# --- File parsing libraries ---
import pdfplumber
import docx
from bs4 import BeautifulSoup
from striprtf.striprtf import rtf_to_text

# --- Google Gemini AI ---
import google.generativeai as genai

# --- Project-specific imports ---
# These import from your other project files
import models
from models import User, Job, Application # Added Application model
# CORRECTED: Imports now match the schemas file you provided
from schemas import UserCreate, User, JobCreate, Job, ApplicationCreate, Application, Token
# Assuming 'auth.py' and 'database.py' exist and are correctly configured
# You will need to create an 'auth.py' file with these functions
from auth import get_password_hash, verify_password, create_access_token, oauth2_scheme, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from database import SessionLocal, engine

# --- Initial Setup ---
load_dotenv()

# Create all database tables based on your models
models.Base.metadata.create_all(bind=engine)

app = FastAPI()

RESUME_UPLOAD_DIR = "resumes" # Directory to store uploaded resumes


# --- CORS Middleware ---
# This allows your frontend (e.g., running on localhost:3000) to communicate with your backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Configure Google Gemini AI ---
try:
    genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
except Exception as e:
    print(f"Warning: Could not configure Gemini API. Resume analysis will not work. Error: {e}")


# --- Dependencies ---
def get_db():
    """Dependency to get a database session for each request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user(db: Session, email: str):
    """Utility function to fetch a user by email."""
    return db.query(models.User).filter(models.User.email == email).first()

async def get_current_active_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Dependency to get the current logged-in user from a JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(db, email=email)
    if user is None:
        raise credentials_exception
    return user

async def get_current_admin_user(current_user: models.User = Depends(get_current_active_user)):
    """Dependency to ensure the current user is an admin."""
    # This now checks the 'role' field as defined in your model
    if current_user.role != 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges, admin access required.")
    return current_user


# --- Helper Functions (Text Extraction & AI Analysis) ---
async def extract_text_from_bytes(content: bytes, filename: str) -> str:
    try:
        ext = os.path.splitext(filename)[1].lower()
        if ext == ".pdf":
            with pdfplumber.open(io.BytesIO(content)) as pdf:
                text = "".join([(p.extract_text() or "") + "\n" for p in pdf.pages])
        elif ext == ".docx":
            doc = docx.Document(io.BytesIO(content))
            text = "\n".join([p.text for p in doc.paragraphs])
        elif ext == ".html":
            text = BeautifulSoup(content, "html.parser").get_text(separator="\n")
        elif ext == ".rtf":
            text = rtf_to_text(content.decode('utf-8', errors='ignore'))
        elif ext == ".txt":
            text = content.decode('utf-8', errors='ignore')
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported file type: {filename}")
        return text
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not process file {filename}: {e}")
   
async def analyze_resume_with_gemini(resume_text: str) -> dict:
    """Uses Google Gemini to extract structured JSON from resume text."""
    if not resume_text:
        return {}
    if not os.getenv("GEMINI_API_KEY"):
        return {"error": "Gemini API key not configured on server."}

    model = genai.GenerativeModel('gemini-1.5-flash-latest')
    generation_config = genai.types.GenerationConfig(response_mime_type="application/json")
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
        f"--- RESUME TEXT ---\n{resume_text}"
    )
    try:
        response = await model.generate_content_async(prompt, generation_config=generation_config)
        return json.loads(response.text)
    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        return {"error": f"Failed to analyze resume with AI: {e}"}


# --- API Endpoints ---
@app.post("/register/", response_model=User, tags=["Authentication"]) # CORRECTED
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    """Registers a new user, hashes their password, and sets default roles."""
    if get_user(db, email=user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    db_user = models.User(
        email=user.email,
        full_name=user.full_name,
        hashed_password=get_password_hash(user.password),
        role='candidate' # All new users are candidates by default
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token", response_model=Token, tags=["Authentication"])
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Handles user login and returns a JWT access token."""
    user = get_user(db, email=form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=User, tags=["Users"]) # CORRECTED
async def read_current_user(current_user: models.User = Depends(get_current_active_user)):
    """Returns the details of the currently authenticated user."""
    return current_user

@app.post("/resume/analyze/", tags=["Resume Analysis"])
async def analyze_resume(
    resume: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    try:
        ext = os.path.splitext(resume.filename)[1].lower()
        if ext not in [".pdf", ".doc", ".docx", ".html", ".rtf", ".txt"]:
            raise HTTPException(status_code=400, detail="Unsupported file type.")

        os.makedirs("resumes", exist_ok=True)
        filename = f"{current_user.full_name}_{current_user.id}{ext}"
        file_path = os.path.join("resumes", filename)

        content = await resume.read()

        with open(file_path, "wb") as buffer:
            buffer.write(content)

        resume_text = await extract_text_from_bytes(content, resume.filename)
        if not resume_text:
            raise HTTPException(status_code=400, detail="Could not extract text from file.")

        analysis = await analyze_resume_with_gemini(resume_text)
        if "error" in analysis:
            raise HTTPException(status_code=500, detail=analysis["error"])

        current_user.resume_filename = filename
        db.commit()

        return {
            "message": "Resume analyzed and stored successfully.",
            "resume_filename": filename,
            "analysis": analysis
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/jobs/", response_model=Job, tags=["Jobs (Admin)"]) # CORRECTED
def create_job(job: JobCreate, db: Session = Depends(get_db), admin_user: models.User = Depends(get_current_admin_user)):
    """Creates a new job posting. Requires admin privileges."""
    db_job = models.Job(**job.model_dump())
    db.add(db_job)
    db.commit()
    db.refresh(db_job)
    return db_job

@app.post("/applications/", response_model=Application)
def submit_application(
    application_data: ApplicationCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    # Clean job title for case-insensitive match
    job_title_cleaned = application_data.job_title.strip().lower()

    job = db.query(models.Job).filter(func.lower(models.Job.title) == job_title_cleaned).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job with title '{application_data.job_title}' not found."
        )
    resume_filename = current_user.resume_filename if current_user.resume_filename else None
    # Create and store application
    db_application = models.Application(
        job_id=job.id,
        user_id=current_user.id,
        salary_expectation=application_data.salary_expectation,
        skills=application_data.skills,
        resume_filename=resume_filename,  # Store the resume filename
    )

    db.add(db_application)
    db.commit()
    db.refresh(db_application)

    return db_application
