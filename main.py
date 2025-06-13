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
import auth
import models
import schemas
from database import SessionLocal, engine

# --- Initial Setup ---
load_dotenv()

# Create all database tables based on your models
models.Base.metadata.create_all(bind=engine)

# Configure the Gemini AI client
try:
    genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
except Exception as e:
    print(f"Error configuring Gemini API: {e}")

app = FastAPI(
    title="Remote Job Finder API",
    description="API for analyzing resumes and managing job data.",
    version="1.0.0"
)

# --- CORS Middleware ---
# Allows your React frontend to communicate with this backend
origins = ["http://localhost", "http://localhost:3000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Dependencies ---
def get_db():
    """Dependency to get a database session for each request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user(db: Session, email: str):
    """Utility function to retrieve a user from the database by email."""
    return db.query(models.User).filter(models.User.email == email).first()

async def get_current_active_user(token: str = Depends(auth.oauth2_scheme), db: Session = Depends(get_db)) -> models.User:
    """
    Dependency to get the current authenticated user from a JWT token.
    This protects endpoints.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = schemas.TokenData(email=email)
    except JWTError:
        raise credentials_exception
    
    user = get_user(db, email=token_data.email)
    if user is None or not user.is_active:
        raise credentials_exception
    return user

# --- Helper Functions ---
def extract_text_from_file(file: UploadFile) -> str:
    """Extracts text from various file types (PDF, DOCX, HTML, RTF, TXT)."""
    # This function remains the same as in the previous version
    filename = file.filename
    content = file.file.read()
    text = ""
    try:
        if filename.endswith(".pdf"):
            with pdfplumber.open(io.BytesIO(content)) as pdf:
                text = "".join([(page.extract_text() or "") + "\n" for page in pdf.pages])
        elif filename.endswith(".docx"):
            doc = docx.Document(io.BytesIO(content))
            text = "\n".join([para.text for para in doc.paragraphs])
        elif filename.endswith(".html"):
            soup = BeautifulSoup(content, "html.parser")
            text = soup.get_text(separator="\n")
        elif filename.endswith(".rtf"):
            text = rtf_to_text(content.decode('utf-8', errors='ignore'))
        elif filename.endswith(".txt"):
            text = content.decode('utf-8', errors='ignore')
        elif filename.endswith(".doc"):
            raise HTTPException(status_code=400, detail="Legacy .doc files are not supported. Please convert to .docx or .pdf.")
        return text
    except Exception as e:
        print(f"Error extracting text from {filename}: {e}")
        raise HTTPException(status_code=500, detail=f"Could not process file: {filename}")

async def analyze_resume_with_gemini(resume_text: str) -> dict:
    """Uses a single AI call to classify and extract resume details."""
    # This function also remains the same
    if not resume_text: return {}
    model = genai.GenerativeModel('gemini-1.5-flash-latest')
    prompt = (
        "Analyze the following resume text. Perform two tasks and return the result as a single, valid JSON object. "
        "Do not include any text or formatting outside of the JSON structure.\n\n"
        "1. **Generate a Job Title**: Create a descriptive, specific job title that summarizes the candidate's expertise (e.g., 'Senior Backend & Django Developer with AI Integration Skills').\n\n"
        "2. **Extract Detailed Information**: Extract the user's full name, email, phone, a list of key skills, and summaries of their experience and education.\n\n"
        "The final JSON object MUST have this structure:\n"
        "{\"suggestedJobTitle\": \"...\", \"details\": {\"fullName\": \"...\", \"email\": \"...\", \"phone\": \"...\", \"keySkills\": [...], \"experienceSummary\": \"...\", \"educationSummary\": \"...\"}}\n\n"
        f"Resume Text:\n---\n{resume_text}"
    )
    try:
        response = await model.generate_content_async(prompt)
        cleaned_text = response.text.strip().replace("```json", "").replace("```", "")
        return json.loads(cleaned_text)
    except Exception as e:
        print(f"Error calling or parsing Gemini response: {e}")
        return {"error": "Failed to analyze resume."}

# --- API Endpoints ---

# --- Authentication Endpoints ---
@app.post("/register/", response_model=schemas.UserSchema, tags=["Authentication"])
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """Registers a new user."""
    db_user = get_user(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token", response_model=schemas.Token, tags=["Authentication"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Provides an access token for a valid user."""
    user = get_user(db, email=form_data.username)
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    access_token = auth.create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# --- User Endpoints ---
@app.get("/users/me/", response_model=schemas.UserSchema, tags=["Users"])
async def read_users_me(current_user: models.User = Depends(get_current_active_user)):
    """Fetches the current logged-in user's details."""
    return current_user

# --- Resume Analysis Endpoint ---
@app.post("/resume/analyze/", tags=["Resume"])
async def upload_and_analyze_resume(resume: UploadFile = File(...), current_user: models.User = Depends(get_current_active_user)):
    """Analyzes an uploaded resume file for a logged-in user."""
    ALLOWED_EXTENSIONS = {".pdf", ".docx", ".html", ".rtf", ".txt"}
    file_ext = os.path.splitext(resume.filename)[1].lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Invalid file type. Supported types are: {', '.join(ALLOWED_EXTENSIONS)}")
    
    try:
        resume_text = extract_text_from_file(resume)
        if not resume_text:
            raise HTTPException(status_code=400, detail="Could not extract text from the uploaded file.")
        
        analysis_result = await analyze_resume_with_gemini(resume_text)
        if "error" in analysis_result:
            raise HTTPException(status_code=500, detail=analysis_result["error"])
        
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {e}")

    return JSONResponse(content={"message": "Resume analyzed successfully.", "analysis": analysis_result})

# --- Job Endpoints ---
@app.get("/jobs/", response_model=List[schemas.JobSchema], tags=["Jobs"])
def read_jobs(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Retrieves a list of all jobs from the database with pagination."""
    jobs = db.query(models.Job).offset(skip).limit(limit).all()
    return jobs
