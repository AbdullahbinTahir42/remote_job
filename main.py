from fastapi import FastAPI,Depends, HTTPException, Request, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import pdfplumber
from sqlalchemy.orm import Session
from models import Job, Base
from database import SessionLocal, engine
import os
import openai
from dotenv import load_dotenv

load_dotenv()
openai.api_key = os.getenv("OPEN_API_KEY")

Base.metadata.create_all(bind=engine)
app = FastAPI()
templates = Jinja2Templates(directory="templates")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def extract_text_from_pdf(filepath: str) -> str:
    text = ""
    with pdfplumber.open(filepath) as pdf:
        for page in pdf.pages:
            text += page.extract_text() or ""
    return text

def ask_chatgpt_to_extract_info(resume_text: str) -> str:
    prompt = (
        "Extract the following info from the resume:\n"
        "- Full Name\n- Email\n- Phone Number\n- Skills\n- Experience\n- Education\n\n"
        f"Resume:\n{resume_text}"
    )
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",  # or "gpt-4" if you have access
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
    )
    return response['choices'][0]['message']['content']

@app.post("/")
async def upload_resume(resume: UploadFile = File(...)):
    if not resume or not resume.filename.endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF resumes are supported")

    file_location = os.path.join(UPLOAD_DIR, resume.filename)
    with open(file_location, "wb") as f:
        content = await resume.read()
        f.write(content)

    try:
        resume_text = extract_text_from_pdf(file_location)
        extracted_info = ask_chatgpt_to_extract_info(resume_text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing resume: {e}")

    return JSONResponse({
        "message": "Resume uploaded and analyzed successfully",
        "extracted_info": extracted_info
    })

@app.get("/jobs/")
def read_jobs(db: Session = Depends(get_db)):
    jobs = db.query(Job).all()
    return jobs


