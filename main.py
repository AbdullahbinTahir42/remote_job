import os
import json
import io
from datetime import timedelta
from typing import List
import re
import logging
from pathlib import Path

# --- Third-party libraries ---
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form, APIRouter, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordRequestForm,HTTPBearer
from sqlalchemy.orm import Session,joinedload
from jose import JWTError, jwt
from sqlalchemy import or_
from multipart import MultipartParser
from io import BytesIO

from email import message
from email.message import EmailMessage

# --- File parsing libraries ---
import pdfplumber
import docx
from bs4 import BeautifulSoup
from striprtf.striprtf import rtf_to_text

# --- Google Gemini AI ---
import google.generativeai as genai

# --- Project-specific imports ---
# Make sure all these files are in the same 'remote_job' directory
# --- Project-specific imports ---
from . import models
from . import schemas
from .auth import get_password_hash, verify_password, create_access_token,        oauth2_scheme, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES   
from .database import SessionLocal, engine

# --- Initial Setup ---
load_dotenv()


logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("AUTH_DEBUG")

# --- DEPLOYMENT BEST PRACTICE: Commented out create_all ---
# In production, you should manage your database with a migration tool like Alembic.
# Running `create_all` on every startup can be risky.
#models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="HR Job Portal API",
    description="API for managing jobs, candidates, and applications.",
    version="1.0.0",
    redirect_slashes=False  # ðŸ‘ˆ Prevent CORS-breaking redirects
)


# --- Define Constants ---
RESUME_UPLOAD_DIR = "resumes"
RECEIPT_UPLOAD_DIR = "receipts"


security = HTTPBearer(auto_error=False)

# --- Serve Static Files (Uploaded Resumes/Receipts) ---
# Ensure these directories exist at the root of your application (`hr_fastapi_backend`)
# --- Ensure Upload Folders Exist ---
os.makedirs(RESUME_UPLOAD_DIR, exist_ok=True)
os.makedirs(RECEIPT_UPLOAD_DIR, exist_ok=True)

# --- Serve Static Files ---
app.mount(f"/{RESUME_UPLOAD_DIR}", StaticFiles(directory=RESUME_UPLOAD_DIR), name="resumes")
app.mount(f"/{RECEIPT_UPLOAD_DIR}", StaticFiles(directory=RECEIPT_UPLOAD_DIR), name="receipts")


# --- CORS Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://hr.growvy.online"],  # Corrected: No trailing slash
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept","Origin","X-Requested-With"],
)

# --- Configure Google Gemini AI ---
try:
    genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
except Exception as e:
    print(f"Warning: Could not configure Gemini API. Resume analysis may not work. Error: {e}")

# --- Dependencies ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Database Helper Function ---
def get_user(db: Session, email: str):
    """
    Fetches a single user from the database using a case-insensitive email search.
    """
    return db.query(models.User).filter(models.User.email.ilike(email)).first()

# --- Security Dependency ---
async def get_current_active_user(
    request: Request,
    token: str = Depends(security),
    db: Session = Depends(get_db)
):
    logger.info("🔍 get_current_active_user called!")
    
    # Check for Authorization header (both standard and http-prefixed)
    auth_header = (request.headers.get("Authorization") or 
                   request.headers.get("authorization") or
                   request.headers.get("http-authorization"))
    
    logger.info(f"🔗 Full Authorization header: {auth_header}")
    
    # Log all headers for debugging
    logger.info(f"📋 All request headers: {dict(request.headers)}")
    
    # Manual token extraction since HTTPBearer might not work with http-prefixed headers
    manual_token = None
    if auth_header and auth_header.startswith("Bearer "):
        manual_token = auth_header.split(" ")[1]
        logger.info(f"🎫 Manually extracted token (first 20 chars): {manual_token[:20]}...")
    
    # Use manual token if dependency token is None
    final_token = token or manual_token
    
    if final_token is None:
        logger.error("❌ No token provided in Authorization header")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing or invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    logger.info(f"🎯 Using token (first 20 chars): {final_token[:20]}...")
    
    # Confirm we're getting the token from the header
    if auth_header:
        if auth_header.startswith("Bearer "):
            extracted_token = auth_header.split(" ")[1]
            logger.info(f"🎫 Token extracted from header (first 20 chars): {extracted_token[:20]}...")
            
            # Verify that our final token matches
            if final_token == extracted_token:
                logger.info("✅ Final token matches manually extracted token")
            else:
                logger.warning("⚠️ Token mismatch between dependency and manual extraction!")
        else:
            logger.error("❌ Authorization header doesn't start with 'Bearer '")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization header format",
                headers={"WWW-Authenticate": "Bearer"},
            )
    else:
        logger.error("❌ No Authorization header found in request")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    logger.info(f"🎫 Final token being used (first 20 chars): {final_token[:20] if final_token else 'None'}...")
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        logger.info("🔧 Starting JWT decode...")
        payload = jwt.decode(final_token, SECRET_KEY, algorithms=[ALGORITHM])  # Use final_token instead of token
        logger.info(f"📦 JWT decoded successfully: {payload}")
        
        email: str = payload.get("sub")
        logger.info(f"📧 Email from token: {email}")
        
        if email is None:
            logger.error("❌ No email found in token payload")
            raise credentials_exception
            
    except JWTError as e:
        logger.error(f"❌ JWT decode error: {e}")
        raise credentials_exception
    except Exception as e:
        logger.error(f"❌ Unexpected error during token decode: {e}")
        raise credentials_exception
    
    logger.info(f"🔍 Looking for user in database: {email}")
    user = get_user(db, email=email)
    
    if user is None:
        logger.error(f"❌ User not found in database for email: {email}")
        raise credentials_exception
        
    logger.info(f"✅ User found: {user.email}")
    return user


    

async def get_current_admin_user(current_user: models.User = Depends(get_current_active_user)):
    if current_user.role != 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough privileges, admin access required.")
    return current_user

# --- Helper Functions ---
async def extract_text_from_bytes(content: bytes, filename: str) -> str:
    """
    Extracts text from the content of a file based on its extension.
    """
    ext = os.path.splitext(filename)[1].lower()
    text = ""
    try:
        logger.info(f"Extracting text from {filename} with extension {ext}")
        if ext == ".pdf":
            with pdfplumber.open(io.BytesIO(content)) as pdf:
                text = "".join([(p.extract_text() or "") + "\n" for p in pdf.pages])
        elif ext == ".docx":
            doc = docx.Document(io.BytesIO(content))
            text = "\n".join([p.text for p in doc.paragraphs])
        elif ext == ".html":
            text = BeautifulSoup(content, "html.parser").get_text(separator="\n")
        elif ext == ".rtf":
            # striprtf expects a string, so we decode the bytes
            text = rtf_to_text(content.decode('utf-8', errors='ignore'))
        elif ext == ".txt":
            text = content.decode('utf-8', errors='ignore')
        else:
            # This case should ideally be caught by the initial validation
            raise HTTPException(status_code=400, detail=f"Unsupported file type: {filename}")
        
        if not text.strip():
            raise ValueError("Extracted text is empty, the document might be an image-based file or blank.")
        return text
    except Exception as e:
        logger.error(f"Failed to extract text from {filename}: {e}", exc_info=True)
        # Provide a more specific error message to the user
        raise HTTPException(status_code=500, detail=f"Could not process file '{filename}'. It might be corrupted, password-protected, or in an unreadable format.")

        
        
async def analyze_resume_with_gemini(resume_text: str) -> dict:
    # ... (code for analyze_resume_with_gemini remains the same)
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

# ==============================================================================
# --- API ROUTERS for Better Organization ---
# ==============================================================================

# --- Authentication and User Router ---
auth_router = APIRouter(tags=["Authentication & Users"])


@auth_router.post("/register", response_model=schemas.S_User)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    
    if get_user(db, email=user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user = models.User(
        email=user.email, full_name=user.full_name, phone_number=user.phone_number,
        hashed_password=get_password_hash(user.password), role='candidate'
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
    
@auth_router.post("/token", response_model=schemas.Token)
async def login(data: schemas.UserLogin, db: Session = Depends(get_db)):
    user = get_user(db, email=data.email)  # ✅ FIXED
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": access_token, "token_type": "bearer"}

@auth_router.get("/users/me", response_model=schemas.S_User)
async def read_current_user(current_user: models.User = Depends(get_current_active_user)):
    return current_user


@auth_router.get("/me")
async def get_current_user_info(
    user: models.User = Depends(get_current_active_user),  # ← This automatically uses the enhanced version
    db: Session = Depends(get_db)
):
    logger.info("🎯 /me endpoint called!")
    
    payment_status = "Pending"
    if user.profile_status != "No" and getattr(user, "profile", None):
        payment_status = user.profile.payment_status
        
    logger.info(f"✅ Returning user info for: {user.email}")
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "profile_status": user.profile_status,
        "role": user.role,
        "payment": payment_status,
    }

    
# --- Profiles and Applications Router ---
profiles_router = APIRouter(tags=["Profiles & Applications"])

@profiles_router.post("/profiles", response_model=schemas.CreateProfile)
def create_profile(profile_data: schemas.NewProfile, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_active_user)):
    job_title = profile_data.job_title.strip().lower()
    current_user.profile_status = "YES"
    if current_user.profile:
        db.delete(current_user.profile)
        db.commit()
    salary_string = f"{profile_data.salary_expectation.amount} {profile_data.salary_expectation.type}" if profile_data.salary_expectation else None
    db_profile = models.Profile(
        user_id=current_user.id, full_name=current_user.full_name, email=current_user.email,
        salary_expectation=salary_string, job_title=job_title, skills=",".join(profile_data.skills),
        remote_type=profile_data.remote_type, location=profile_data.location,
        benefits=",".join(profile_data.benefits) if profile_data.benefits else None,
        career_level=profile_data.career_level, work_type=profile_data.work_type,
        resume_filename=current_user.resume_filename if current_user.resume_filename else None
    )
    db.add(db_profile)
    db.commit()
    db.refresh(db_profile)
    return db_profile

@profiles_router.get("/profile")
def get_profile(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_active_user)):
    profile = db.query(models.Profile).filter(models.Profile.user_id == current_user.id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile

@profiles_router.post("/applications", response_model=schemas.S_Application)
def apply_to_job(application: schemas.ApplicationCreate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_active_user)):
    if not db.query(models.Job).filter(models.Job.id == application.job_id).first():
        raise HTTPException(status_code=404, detail="Job not found")
    if db.query(models.Application).filter(models.Application.user_id == current_user.id, models.Application.job_id == application.job_id).first():
        raise HTTPException(status_code=400, detail="Already applied to this job")
    new_application = models.Application(user_id=current_user.id, **application.model_dump())
    db.add(new_application)
    db.commit()
    db.refresh(new_application)
    return new_application

# --- Jobs Router ---
jobs_router = APIRouter(tags=["Jobs"])

@jobs_router.get("/user_jobs", response_model=List[schemas.S_Job])
def get_user_related_jobs(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_active_user)):
    profile = current_user.profile
    if not profile or (not profile.job_title and not profile.skills):
        return []
    def extract_keywords(text):
        return set(re.findall(r'\b\w+\b', text.lower()))
    all_keywords = extract_keywords(profile.job_title or "") | set(k for s in (profile.skills or "").split(",") for k in extract_keywords(s))
    if not all_keywords:
        return []
    filters = [or_(models.Job.title.ilike(f"%{kw}%"), models.Job.description.ilike(f"%{kw}%")) for kw in all_keywords]
    return db.query(models.Job).filter(or_(*filters)).all()


# --- File Uploads and Payments Router ---
uploads_router = APIRouter(tags=["File Uploads & Payments"])


@uploads_router.post("/resume/analyze")
async def analyze_resume_manual(
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user),
):
    
    
    ALLOWED_EXTENSIONS = {".pdf", ".doc", ".docx", ".html", ".rtf", ".txt"}
    
    try:
        logger.info("🔍 Starting manual resume analysis...")
        
        # Get content type and raw body
        content_type = request.headers.get("content-type", "")
        raw_body = await request.body()
        
        logger.info(f"📋 Content-Type: {content_type}")
        logger.info(f"📏 Body length: {len(raw_body)} bytes")
        
        if len(raw_body) < 100:
            logger.error("❌ Request body too small")
            raise HTTPException(status_code=400, detail="Request body too small.")
        
        # Extract boundary from Content-Type header (more reliable)
        boundary = None
        if "multipart/form-data" in content_type:
            boundary_match = re.search(r'boundary=([^;]+)', content_type)
            if boundary_match:
                boundary = boundary_match.group(1).strip('"')
                logger.info(f"🔗 Boundary from header: {boundary}")
        
        # Fallback: extract boundary from body
        if not boundary:
            body_str = raw_body.decode('utf-8', errors='ignore')
            boundary_match = re.search(r'------WebKitFormBoundary[A-Za-z0-9]+', body_str)
            if boundary_match:
                boundary = boundary_match.group(0)
                logger.info(f"🔗 Boundary from body: {boundary}")
        
        if not boundary:
            logger.error("❌ Could not find boundary")
            raise HTTPException(status_code=400, detail="Could not find multipart boundary.")
        
        # Parse multipart data manually
        boundary_bytes = f"--{boundary}".encode() if not boundary.startswith('--') else boundary.encode()
        parts = raw_body.split(boundary_bytes)
        
        logger.info(f"📦 Found {len(parts)} parts in multipart data")
        
        resume_file = None
        filename = None
        resume_content = None
        
        # Process each part
        for i, part in enumerate(parts):
            if len(part) < 10:  # Skip empty parts
                continue
                
            logger.info(f"🔍 Processing part {i}, size: {len(part)} bytes")
            
            # Look for the resume field
            if b'name="resume"' in part or b"name='resume'" in part:
                logger.info("📎 Found resume part!")
                
                # Extract headers and content
                if b'\r\n\r\n' in part:
                    headers_section, content_section = part.split(b'\r\n\r\n', 1)
                elif b'\n\n' in part:
                    headers_section, content_section = part.split(b'\n\n', 1)
                else:
                    logger.warning("⚠️ Could not split headers from content")
                    continue
                
                headers_str = headers_section.decode('utf-8', errors='ignore')
                logger.info(f"📋 Part headers: {headers_str}")
                
                # Extract filename
                filename_patterns = [
                    rb'filename="([^"]+)"',
                    rb"filename='([^']+)'",
                    rb'filename=([^\s;]+)',
                ]
                
                for pattern in filename_patterns:
                    filename_match = re.search(pattern, part)
                    if filename_match:
                        filename = filename_match.group(1).decode('utf-8')
                        logger.info(f"📄 Extracted filename: {filename}")
                        break
                
                # Clean up content (remove trailing boundary markers)
                resume_content = content_section
                if resume_content.endswith(b'\r\n'):
                    resume_content = resume_content[:-2]
                if resume_content.endswith(b'\n'):
                    resume_content = resume_content[:-1]
                
                logger.info(f"📄 File content size: {len(resume_content)} bytes")
                break
        
        # Validation
        if not filename:
            logger.error("❌ No filename found")
            raise HTTPException(status_code=400, detail="No filename found in form data.")
            
        if not resume_content:
            logger.error("❌ No file content found")
            raise HTTPException(status_code=400, detail="No file content found in form data.")
        
        # Validate file extension
        ext = os.path.splitext(filename)[1].lower()
        logger.info(f"📎 File extension: {ext}")
        
        if ext not in ALLOWED_EXTENSIONS:
            logger.error(f"❌ Unsupported file type: {ext}")
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type '{ext}'. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
            )
        
        # Validate file size
        if len(resume_content) < 50:
            logger.error("❌ File content too small")
            raise HTTPException(
                status_code=400,
                detail="File content too small. Ensure it's a valid resume."
            )
        
        logger.info(f"✅ File validation passed: {filename} ({len(resume_content)} bytes)")
        
        # Generate safe filename
        safe_name = "".join(c for c in current_user.full_name if c.isalnum() or c in {' ', '_'}).replace(" ", "_")
        new_filename = f"{safe_name}_{current_user.id}{ext}"
        
        logger.info(f"💾 Saving as: {new_filename}")
        
        # Create directory and save file
        resume_dir = Path(RESUME_UPLOAD_DIR)
        resume_dir.mkdir(parents=True, exist_ok=True)
        file_path = resume_dir / new_filename
        
        with open(file_path, "wb") as f:
            f.write(resume_content)
        
        logger.info(f"✅ File saved to: {file_path}")
        
        # Update user record
        user = db.query(models.User).filter_by(id=current_user.id).first()
        if not user:
            logger.error("❌ User not found in database")
            raise HTTPException(status_code=404, detail="User not found.")
        
        user.resume_filename = new_filename
        db.commit()
        
        logger.info("✅ User record updated")
        
        # Process resume
        logger.info("🔧 Starting resume text extraction...")
        resume_text = await extract_text_from_bytes(resume_content, new_filename)
        
        logger.info("🤖 Starting Gemini analysis...")
        analysis = await analyze_resume_with_gemini(resume_text)
        
        logger.info("✅ Resume analysis completed successfully")
        
        return {
            "message": "Resume analyzed and saved successfully.",
            "filename": new_filename,
            "analysis": analysis,
            "file_size": len(resume_content),
            "original_filename": filename
        }
        
    except HTTPException as e:
        logger.error(f"❌ HTTP Exception: {e.detail}")
        raise
    except Exception as e:
        logger.error(f"🔥 Unexpected error during resume processing: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during resume processing.")



@uploads_router.post("/payment/submit")
async def submit_payment(
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_active_user)
):
    try:
        logger.info("💳 Starting payment submission...")
        
        # Get content type and raw body
        content_type = request.headers.get("content-type", "")
        raw_body = await request.body()
        
        logger.info(f"📋 Content-Type: {content_type}")
        logger.info(f"📏 Body length: {len(raw_body)} bytes")
        
        if len(raw_body) < 100:
            logger.error("❌ Request body too small")
            raise HTTPException(status_code=400, detail="Request body too small.")
        
        # Extract boundary from Content-Type header (more reliable)
        boundary = None
        if "multipart/form-data" in content_type:
            boundary_match = re.search(r'boundary=([^;]+)', content_type)
            if boundary_match:
                boundary = boundary_match.group(1).strip('"')
                logger.info(f"🔗 Boundary from header: {boundary}")
        
        # Fallback: extract boundary from body
        if not boundary:
            body_str = raw_body.decode('utf-8', errors='ignore')
            boundary_match = re.search(r'------WebKitFormBoundary[A-Za-z0-9]+', body_str)
            if boundary_match:
                boundary = boundary_match.group(0)
                logger.info(f"🔗 Boundary from body: {boundary}")
        
        if not boundary:
            logger.error("❌ Could not find boundary")
            raise HTTPException(status_code=400, detail="Could not find multipart boundary.")
        
        # Parse multipart data manually
        boundary_bytes = f"--{boundary}".encode() if not boundary.startswith('--') else boundary.encode()
        parts = raw_body.split(boundary_bytes)
        
        logger.info(f"📦 Found {len(parts)} parts in multipart data")
        
        # Storage for form data and files
        form_data = {}
        files = {}
        
        # Process each part
        for i, part in enumerate(parts):
            if len(part) < 10:  # Skip empty parts
                continue
                
            logger.info(f"🔍 Processing part {i}, size: {len(part)} bytes")
            
            # Split headers from content
            if b'\r\n\r\n' in part:
                headers_section, content_section = part.split(b'\r\n\r\n', 1)
            elif b'\n\n' in part:
                headers_section, content_section = part.split(b'\n\n', 1)
            else:
                logger.warning(f"⚠️ Could not split headers from content in part {i}")
                continue
            
            headers_str = headers_section.decode('utf-8', errors='ignore')
            logger.info(f"📋 Part {i} headers: {headers_str}")
            
            # Extract field name
            name = None
            filename = None
            
            # Look for name attribute
            name_patterns = [
                rb'name="([^"]+)"',
                rb"name='([^']+)'",
                rb'name=([^\s;]+)',
            ]
            
            for pattern in name_patterns:
                name_match = re.search(pattern, part)
                if name_match:
                    name = name_match.group(1).decode('utf-8')
                    logger.info(f"📝 Extracted field name: {name}")
                    break
            
            # Check if it's a file (has filename attribute)
            filename_patterns = [
                rb'filename="([^"]+)"',
                rb"filename='([^']+)'",
                rb'filename=([^\s;]+)',
            ]
            
            for pattern in filename_patterns:
                filename_match = re.search(pattern, part)
                if filename_match:
                    filename = filename_match.group(1).decode('utf-8')
                    logger.info(f"📄 Extracted filename: {filename}")
                    break
            
            if not name:
                logger.warning(f"⚠️ No name found for part {i}")
                continue
            
            # Clean up content (remove trailing boundary markers)
            content = content_section
            if content.endswith(b'\r\n'):
                content = content[:-2]
            if content.endswith(b'\n'):
                content = content[:-1]
            
            if filename:  # It's a file
                files[name] = {
                    'filename': filename,
                    'content': content
                }
                logger.info(f"📁 Added file: {name} = {filename} ({len(content)} bytes)")
            else:  # It's a form field
                field_value = content.decode('utf-8', errors='ignore').strip()
                form_data[name] = field_value
                logger.info(f"📝 Added field: {name} = {field_value}")
        
        logger.info(f"📊 Final form_data: {list(form_data.keys())}")
        logger.info(f"📁 Final files: {list(files.keys())}")
        
        # Extract and validate form fields
        name = form_data.get('name')
        email = form_data.get('email')
        plan = form_data.get('plan')
        method = form_data.get('method')
        termsAccepted = form_data.get('termsAccepted')
        
        # Extract receipt file
        receipt_file = files.get('receipt')
        
        # Validate required fields
        missing_fields = []
        if not name:
            missing_fields.append('name')
        if not email:
            missing_fields.append('email')
        if not plan:
            missing_fields.append('plan')
        if not method:
            missing_fields.append('method')
        if not termsAccepted:
            missing_fields.append('termsAccepted')
        
        if missing_fields:
            logger.error(f"❌ Missing required fields: {missing_fields}")
            raise HTTPException(
                status_code=422, 
                detail=f"Missing required fields: {', '.join(missing_fields)}"
            )
        
        if not receipt_file:
            logger.error("❌ Receipt file is required")
            raise HTTPException(status_code=422, detail="Receipt file is required")
        
        # Validate receipt file
        receipt_filename = receipt_file['filename']
        if not receipt_filename:
            logger.error("❌ Receipt filename is required")
            raise HTTPException(status_code=422, detail="Receipt filename is required")
        
        receipt_content = receipt_file['content']
        if len(receipt_content) < 50:
            logger.error("❌ Receipt file content too small")
            raise HTTPException(
                status_code=400,
                detail="Receipt file content too small. Ensure it's a valid receipt."
            )
        
        logger.info(f"📄 Receipt file: {receipt_filename} ({len(receipt_content)} bytes)")
        
        # Check if email matches current user's email
        if email != current_user.email:
            logger.error(f"❌ Email mismatch: {email} != {current_user.email}")
            raise HTTPException(status_code=400, detail="Email must match your account email.")
        
        # Check if payment already exists for this email
        existing_payment = db.query(models.Payment).filter(models.Payment.email == email).first()
        if existing_payment:
            logger.error(f"❌ Payment already exists for email: {email}")
            raise HTTPException(status_code=400, detail="Payment already exists for this email.")
        
        # Convert termsAccepted to boolean
        terms_accepted_bool = termsAccepted.lower() in ('true', '1', 'yes', 'on')
        
        # Check if terms are accepted
        if not terms_accepted_bool:
            logger.error("❌ Terms must be accepted")
            raise HTTPException(status_code=400, detail="Terms must be accepted.")
        
        # Get user profile
        user = db.query(models.User).filter(models.User.email == email).first()
        if not user or not user.profile:
            logger.error(f"❌ User profile not found for email: {email}")
            raise HTTPException(status_code=404, detail="User profile not found. Please create a profile first.")
        
        # Update payment status
        user.profile.payment_status = "Verifying"
        
        # Generate safe filename
        safe_name = "".join(c for c in user.full_name if c.isalnum() or c in {' ', '_'}).replace(" ", "_")
        ext = os.path.splitext(receipt_filename)[1].lower()
        new_filename = f"{safe_name}_{user.id}{ext}"
        
        logger.info(f"💾 Saving receipt as: {new_filename}")
        
        # Create directory and save file
        receipt_dir = Path(RECEIPT_UPLOAD_DIR)
        receipt_dir.mkdir(parents=True, exist_ok=True)
        file_path = receipt_dir / new_filename
        
        with open(file_path, "wb") as f:
            f.write(receipt_content)
        
        logger.info(f"✅ Receipt saved to: {file_path}")
        
        # Create payment record
        payment = models.Payment(
            profile_id=user.profile.id,
            name=name,
            email=email,
            plan=plan,
            method=method,
            receipt_name=new_filename,
            terms_accepted=terms_accepted_bool
        )
        
        db.add(payment)
        db.commit()
        db.refresh(payment)
        
        logger.info("✅ Payment submitted successfully")
        
        return {
            "message": "Payment submitted successfully.",
            "data": {
                "receipt": new_filename,
                "file_size": len(receipt_content),
                "original_filename": receipt_filename
            }
        }
        
    except HTTPException as e:
        logger.error(f"❌ HTTP Exception: {e.detail}")
        raise
    except Exception as e:
        logger.error(f"🔥 Unexpected error during payment processing: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during payment processing.")


# --- Admin Router ---
admin_router = APIRouter(prefix="/admin", tags=["Admin"], dependencies=[Depends(get_current_admin_user)])

@admin_router.get("/stats")
def stats(db: Session = Depends(get_db)):
    total_users = db.query(models.User).count()
    total_jobs = db.query(models.Job).count()
    total_applications = db.query(models.Application).count()
    total_profiles = db.query(models.Profile).count()
    return {"users": total_users, "jobs": total_jobs, "applications": total_applications, "profiles": total_profiles}

@admin_router.get("/jobs")
def get_jobs(db: Session = Depends(get_db)):
    return db.query(models.Job).all()

@admin_router.post("/jobs", response_model=schemas.S_Job)
def create_job(job: schemas.JobCreate, db: Session = Depends(get_db)):
    db_job = models.Job(**job.model_dump())
    db.add(db_job)
    db.commit()
    db.refresh(db_job)
    return db_job

@admin_router.delete("/jobs/{job_id}")
def delete_job(job_id: int, db: Session = Depends(get_db)):
    job = db.query(models.Job).filter(models.Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    db.delete(job)
    db.commit()
    return {"message": "Job deleted"}

@admin_router.post("/payment/done")
def payment_done(payment: schemas.PaymentRequest, db: Session = Depends(get_db)):
    # Correctly filter by the ID from the payment object
    profile = db.query(models.Profile).filter(models.Profile.id == payment.profile_id).first()

    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found for this user")

    profile.payment_status = "Paid"
    db.commit()

    return {"message": "Payment successful", "profile_id": profile.id}

@admin_router.get("/profiles")
def get_profiles(db: Session = Depends(get_db)):
    return db.query(models.Profile).all()

@admin_router.get("/applications", response_model=List[schemas.ApplicationOut])
def get_applications(db: Session = Depends(get_db)):
    applications = db.query(models.Application).options(
        joinedload(models.Application.user).joinedload(models.User.profile),
        joinedload(models.Application.job)
    ).all()
    return [
        {
            "id": app.id, "user_email": app.user.email, "full_name": app.user.full_name,
            "job_title": app.job.title, "status": app.status, "application_date": app.application_date,
            "resume_filename": app.user.profile.resume_filename if app.user.profile else None
        } for app in applications
    ]

@admin_router.get("/payments/users")
def get_verifying_users_with_payment_plan(db: Session = Depends(get_db)):
    profiles = db.query(models.Profile).filter(models.Profile.payment_status == "Verifying").all()
    return [
        {
            "id": profile.id, "email": profile.email, "full_name": profile.full_name,
            "plan": profile.payment.plan if profile.payment else None,"receipt": profile.payment.receipt_name if profile.payment else None
        } for profile in profiles
    ]

# ==============================================================================
# --- Include Routers in the Main App ---
# ==============================================================================
app.include_router(auth_router)
app.include_router(profiles_router)
app.include_router(jobs_router)
app.include_router(uploads_router)
app.include_router(admin_router)

# --- Root Endpoint ---
@app.get("/")
def home():
    return "Hello There!!! The API is running."
