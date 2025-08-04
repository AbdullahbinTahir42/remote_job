HR Job Portal API
An intelligent, AI-powered backend for a modern job portal application, built with FastAPI and Google Gemini. This API provides a robust foundation for managing users, jobs, candidate profiles, applications, and payments, with a key feature of automated resume analysis.

✨ Key Features
🤖 AI-Powered Resume Parsing: Automatically extracts key information like the candidate's professional role and location from uploaded resumes (.pdf, .docx, .rtf, .txt) using the Google Gemini API.

🔐 Secure Authentication: Implements JWT (JSON Web Token) for secure, token-based user authentication and role-based access control (candidate and admin).

👤 Comprehensive Profile Management: Allows candidates to create and manage detailed professional profiles, including skills, salary expectations, work preferences, and more.

💼 Full Job & Application Lifecycle: Complete CRUD (Create, Read, Update, Delete) functionality for job postings (admin-only) and a seamless application process for candidates.

💰 Payment Verification System: A workflow for users to submit payment receipts for premium features, which an admin can then verify and approve.

🗂️ Admin Dashboard Functionality: Dedicated endpoints for administrators to view statistics, manage all jobs, view candidate profiles, and approve payments.

🔗 Smart Job Matching: A basic recommendation engine that suggests relevant jobs to users based on their profile's job title and skills.

🛠️ Technology Stack
Backend Framework: FastAPI

Database: SQLAlchemy ORM (compatible with PostgreSQL, SQLite, etc.)

Authentication: python-jose for JWT, passlib with bcrypt for password hashing.

AI Integration: Google Gemini (google-generativeai)

Data Validation: Pydantic

File Parsing: pdfplumber, python-docx, BeautifulSoup, striprtf

API Server: Uvicorn

🚀 Getting Started
Follow these instructions to get the project up and running on your local machine.

Prerequisites
Python 3.8+

A relational database (e.g., PostgreSQL, SQLite)

A Google Gemini API Key

Installation
Clone the repository:

Bash

git clone <[your-repository-url>](https://github.com/AbdullahbinTahir42/remote_job)
Create and activate a virtual environment:

On Windows:

Bash

python -m venv venv
.\venv\Scripts\activate
On macOS/Linux:

Bash

python3 -m venv venv
source venv/bin/activate
Install the required dependencies:

Bash

pip install -r requirements.txt
Configure environment variables:
Create a file named .env in the project root directory. Copy the contents of the example below and fill in your actual values.

.env.example

Code snippet

# This is an example. Create a .env file with your actual credentials.

# Gemini API Key for resume analysis
GEMINI_API_KEY="your_google_gemini_api_key"

# JWT Authentication Settings
SECRET_KEY="your_super_secret_key_for_jwt" # Generate a strong random key
ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=60

# Database URL (Example for SQLite)
# For PostgreSQL, it would be: DATABASE_URL="postgresql://user:password@host:port/dbname"
DATABASE_URL="sqlite:///./jobportal.db"
Database Setup:
The application uses SQLAlchemy to manage the database schema. While create_all is present, it's commented out as a best practice for production. For a real deployment, use a migration tool like Alembic. For local development, you can uncomment the models.Base.metadata.create_all(bind=engine) line in main.py for the initial run to create the tables.

Run the application:

Bash

uvicorn main:app --reload
The API will be available at http://127.0.0.1:8000. You can access the interactive API documentation at http://127.0.0.1:8000/docs.

📝 API Endpoints
Here is a summary of the available API endpoints.

Authentication & Users
Method	Path	Description	Protected
POST	/register	Register a new candidate user.	No
POST	/token	Log in to get a JWT access token.	No
GET	/users/me	Get details of the currently logged-in user.	Yes
GET	/me	Get concise info for the logged-in user.	Yes

Export to Sheets
Profiles & Applications
Method	Path	Description	Protected
POST	/profiles	Create or update the user's profile.	Yes
GET	/profile	Get the current user's profile.	Yes
POST	/applications	Apply for a specific job.	Yes

Export to Sheets
Jobs
Method	Path	Description	Protected
GET	/user_jobs	Get jobs recommended for the current user.	Yes

Export to Sheets
File Uploads & Payments
Method	Path	Description	Protected
POST	/resume/analyze	Upload and analyze a resume using Gemini AI.	Yes
POST	/payment/submit	Submit payment details and a receipt image.	Yes

Export to Sheets
Admin
Note: All admin endpoints require an 'admin' role and are prefixed with /admin.

Method	Path	Description
GET	/stats	Get portal statistics (users, jobs, etc.).
GET	/jobs	Get a list of all jobs.
POST	/jobs	Create a new job posting.
DELETE	/jobs/{job_id}	Delete a specific job.
POST	/payment/done	Mark a user's payment as 'Paid'.
GET	/profiles	Get a list of all candidate profiles.
GET	/applications	Get a list of all job applications.
GET	/payments/users	Get users whose payments are pending verification.

Export to Sheets
💡 Important Notes
Manual Multipart Parsing: The /resume/analyze and /payment/submit endpoints use custom logic to parse multipart/form-data. This was implemented to handle potential inconsistencies from different frontend clients or environments and provides robust, low-level control over file uploads.

CORS Configuration: The Cross-Origin Resource Sharing (CORS) middleware is configured to only allow requests from https://hr.growvy.online. You will need to update this list in main.py to match your frontend's URL.
