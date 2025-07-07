import os
import json
import io
from datetime import timedelta, datetime
from typing import List
import re



# --- Third-party libraries ---
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form,UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session,joinedload
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
# Imports for models and schemas are consolidated
import models
import schemas
# Assuming 'auth.py' and 'database.py' exist and are correctly configured
# You will need to create an 'auth.py' file with these functions
from auth import get_password_hash, verify_password, create_access_token, oauth2_scheme, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from database import SessionLocal, engine

# --- Initial Setup ---
load_dotenv()

# Create all database tables based on your models
#models.Base.metadata.drop_all(bind=engine)
models.Base.metadata.create_all(bind=engine)
  # Clear existing data for a fresh start

app = FastAPI()

RESUME_UPLOAD_DIR = "resumes" # Directory to store uploaded resumes


# --- CORS Middleware ---
# This allows your frontend (e.g., running on localhost:3000) to communicate with your backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # 👈 Match your frontend exactly
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
        raw_output = response.candidates[0].content.parts[0].text
        return json.loads(raw_output)
    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        return {"error": f"Failed to analyze resume with AI: {e}"}

# --- API Endpoints ---
@app.post("/register/", response_model=schemas.S_User, tags=["Authentication"])
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """Registers a new user, hashes their password, and sets default roles."""
    if get_user(db, email=user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    db_user = models.User(
        email=user.email,
        full_name=user.full_name,
        phone_number=user.phone_number,
        hashed_password=get_password_hash(user.password),
        role='candidate' # All new users are candidates by default
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token", response_model=schemas.Token, tags=["Authentication"])
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Handles user login and returns a JWT access token."""
    user = get_user(db, email=form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=schemas.S_User, tags=["Users"])
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


@app.post("/jobs/", response_model=schemas.S_Job, tags=["Jobs (Admin)"])
def create_job(job: schemas.JobCreate, db: Session = Depends(get_db), admin_user: models.User = Depends(get_current_admin_user)):
    """Creates a new job posting. Requires admin privileges."""
    db_job = models.Job(**job.model_dump())
    db.add(db_job)
    db.commit()
    db.refresh(db_job)
    return db_job




@app.get("/user_jobs/", response_model=List[schemas.S_Job])
def get_user_related_jobs(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    profile = current_user.profile

    if not profile or (not profile.job_title and not profile.skills):
        return []

    filters = []
    query = db.query(models.Job)

    def extract_keywords(text):
        # Convert to lowercase and extract words only (no punctuation)
        words = re.findall(r'\b\w+\b', text.lower())
        return set(words)

    title_keywords = extract_keywords(profile.job_title or "")
    skill_keywords = set()
    for skill in (profile.skills or "").split(","):
        skill_keywords.update(extract_keywords(skill))

    all_keywords = title_keywords.union(skill_keywords)

    for keyword in all_keywords:
        filters.append(models.Job.title.ilike(f"%{keyword}%"))
        filters.append(models.Job.description.ilike(f"%{keyword}%"))

    jobs = query.filter(or_(*filters)).all()
    return jobs


@app.post("/profiles/", response_model= schemas.CreateProfile)
def Create_Profile(
    profile_data: schemas.NewProfile,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    # Normalize job title for case-insensitive search
    job_title = profile_data.job_title.strip().lower()
    current_user.profile_status = "YES"
    existing_profile = current_user.profile
    if existing_profile:
        db.delete(existing_profile)
        db.commit()

    # Create and store the new application
    # --- Previous code in your API endpoint ---

# Create and store the new application
    salary_string = None
    if profile_data.salary_expectation:
    # Format the salary object into a single string
        salary_string = f"{profile_data.salary_expectation.amount} {profile_data.salary_expectation.type}"

    db_profile = models.Profile(
        
        user_id=current_user.id,
        full_name=current_user.full_name,
        email=current_user.email,
    
    # Correctly assign the formatted string to the database column
        salary_expectation=salary_string,
        job_title= job_title,
        skills=",".join(profile_data.skills),
        remote_type=profile_data.remote_type,
        location=profile_data.location,
        benefits=",".join(profile_data.benefits) if profile_data.benefits else None,
        career_level=profile_data.career_level,
        work_type=profile_data.work_type,
        resume_filename=current_user.resume_filename if current_user.resume_filename else None,
    # You can remove application_date and status as they have default values in the model
        )

    db.add(db_profile)
    db.commit()
    db.refresh(db_profile)

    return db_profile

    




@app.get("/profile/")
def get_profile(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    """Fetches the profile of the currently authenticated user."""
    profile = db.query(models.Profile).filter(models.Profile.user_id == current_user.id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile


@app.get("/me")
def get_current_user_info(current_user: models.User = Depends(get_current_active_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "profile_status": current_user.profile_status,
        "role" : current_user.role
    }

@app.post("/applications/", response_model=schemas.S_Application)
def apply_to_job(
    application: schemas.ApplicationCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    # Check if job exists
    job = db.query(models.Job).filter(models.Job.id == application.job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # Optional: Prevent duplicate applications
    existing_application = db.query(models.Application).filter(
        models.Application.user_id == current_user.id,
        models.Application.job_id == application.job_id
    ).first()
    if existing_application:
        raise HTTPException(status_code=400, detail="Already applied to this job")

    # Create new application
    new_application = models.Application(
        user_id=current_user.id,
        job_id=application.job_id,
        cover_letter=application.cover_letter
    )
    db.add(new_application)
    db.commit()
    db.refresh(new_application)

    return new_application


@app.get("/admin/stats", tags=["Admin"])
def stats(db: Session = Depends(get_db)):
    total_users = db.query(models.User).count()
    total_jobs = db.query(models.Job).count()
    total_applications = db.query(models.Application).count()
    total_profiles = db.query(models.Profile).count()
    print(f"Total Users: {total_users}, Total Jobs: {total_jobs}, Total Applications: {total_applications}, Total Profiles: {total_profiles}")
    return {
    "users": total_users,
    "jobs": total_jobs,
    "applications": total_applications,
    "profiles": total_profiles
    }

@app.get("/admin/jobs", tags=["Admin"])
def get_jobs(db: Session = Depends(get_db)):

    return db.query(models.Job).all()


@app.post("/admin/jobs", tags=["Admin"])
def create_job(job: schemas.JobCreate, db: Session = Depends(get_db)):
    new_job = models.Job(**job.dict())
    db.add(new_job)
    db.commit()
    db.refresh(new_job)
    return new_job

@app.delete("/admin/jobs/{job_id}", tags=["Admin"])
def delete_job(job_id: int, db: Session = Depends(get_db)):
    job = db.query(models.Job).filter(models.Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    db.delete(job)
    db.commit()
    return {"message": "Job deleted"}


# admin.py or routes/admin/job_routes.py

@app.post("/admin/jobs", response_model=schemas.S_Job, tags=["Admin"])
def create_job(job: schemas.JobCreate, db: Session = Depends(get_db)):
    db_job = models.Job(
        title=job.title,
        location=job.location,
        company=job.company,
        salary=job.salary,
        type=job.type,
        experience=job.experience,
        description=job.description,
    )
    db.add(db_job)
    db.commit()
    db.refresh(db_job)
    return db_job




@app.post("/admin/payment/done")
def payment_done(
    payment: schemas.PaymentRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):


    profile = db.query(models.Profile).filter(models.Profile.id == payment.profile_id).first()

    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found for this user")

    profile.payment_status = "Paid"
    db.commit()

    return {"message": "Payment successful", "profile_id": profile.id}



@app.get("/admin/profiles")
def get_profiles(db: Session = Depends(get_db)):
    return db.query(models.Profile).all()


@app.get("/admin/applications", response_model=List[schemas.ApplicationOut])
def get_applications(db: Session = Depends(get_db)):
    applications = db.query(models.Application).all()
    
    # Collect custom response
    result = []
    for app in applications:
        result.append({
            "id": app.id,
            "user_email": app.user.email,
            "full_name": app.user.full_name,
            "job_title": app.job.title,
            "status": app.status,
            "application_date": app.application_date,
            "cover_letter": app.cover_letter,
        })
    return result

@app.post("/payment/submit")
async def submit_payment(
    name: str = Form(...),
    email: str = Form(...),
    method: str = Form(...),
    termsAccepted: bool = Form(...),
    receipt: UploadFile = File(...)
):
    if not termsAccepted:
        raise HTTPException(status_code=400, detail="Terms must be accepted.")

    # 🧾 Save receipt if needed
    file_location = f"uploads/receipts/{receipt.filename}"
    with open(file_location, "wb") as f:
        f.write(await receipt.read())

    # ✅ You can store this info in a database here
    # e.g., create Payment(name=name, email=email, ...)

    return {
        "message": "Payment submitted successfully",
        "data": {
            "name": name,
            "email": email,
            "method": method,
            "receipt": receipt.filename,
        }
    }