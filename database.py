import os
import logging
from sqlalchemy import create_engine, __version__ as sqlalchemy_version
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Try to import text for SQLAlchemy 2.0+, fallback for older versions
try:
    from sqlalchemy import text
    HAS_TEXT = True
except ImportError:
    HAS_TEXT = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration from environment variables
POSTGRES_USER = os.getenv("POSTGRES_USER", "growendq_hrFastapi")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "Abdullah4200")
POSTGRES_SERVER = os.getenv("POSTGRES_SERVER", "localhost")
POSTGRES_DB = os.getenv("POSTGRES_DB", "growendq_hr_fastapi_db")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")

# Log database configuration (hide password)
logger.info(f"POSTGRES_USER = {POSTGRES_USER}")
logger.info(f"POSTGRES_PASSWORD = {'***' if POSTGRES_PASSWORD else 'Not set'}")
logger.info(f"POSTGRES_SERVER = {POSTGRES_SERVER}")
logger.info(f"POSTGRES_DB = {POSTGRES_DB}")
logger.info(f"POSTGRES_PORT = {POSTGRES_PORT}")

# Validate required configuration
if not POSTGRES_PASSWORD:
    logger.error("POSTGRES_PASSWORD environment variable is required for PostgreSQL connection")
    raise ValueError("POSTGRES_PASSWORD environment variable must be set")

if not POSTGRES_USER:
    logger.error("POSTGRES_USER environment variable is required")
    raise ValueError("POSTGRES_USER environment variable must be set")

# Alternative: Hardcode password for testing (NOT for production)
# DATABASE_URL = "postgresql+psycopg2://growendq_hrFastapi:Abdullah4200@localhost:5432/growendq_hr_fastapi_db"

# Construct database URL with proper URL encoding
from urllib.parse import quote_plus
encoded_password = quote_plus(POSTGRES_PASSWORD)
encoded_user = quote_plus(POSTGRES_USER)

DATABASE_URL = f"postgresql+psycopg2://{encoded_user}:{encoded_password}@{POSTGRES_SERVER}:{POSTGRES_PORT}/{POSTGRES_DB}"

logger.info(f"DATABASE_URL = {DATABASE_URL.replace(POSTGRES_PASSWORD, '***') if POSTGRES_PASSWORD else DATABASE_URL}")
logger.info(f"SQLAlchemy version = {sqlalchemy_version}")

# Create engine
try:
    engine = create_engine(
        DATABASE_URL,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        echo=False,  # Set to True for SQL query logging
        connect_args={
            "connect_timeout": 30,
            "application_name": "hr_fastapi_backend"
        }
    )
    logger.info("Database engine created successfully")
except Exception as e:
    logger.error(f"Failed to create database engine: {e}")
    raise

# Create declarative base
Base = declarative_base()

# Test database connection with version-specific approach
def test_connection():
    """Test database connection with appropriate method based on SQLAlchemy version"""
    try:
        with engine.connect() as conn:
            if HAS_TEXT:
                # SQLAlchemy 2.0+ approach
                result = conn.execute(text("SELECT 1 as test"))
                logger.info("Database connection successful (SQLAlchemy 2.0+ method)")
            else:
                # SQLAlchemy 1.x approach
                result = conn.execute("SELECT 1 as test")
                logger.info("Database connection successful (SQLAlchemy 1.x method)")
            
            # Fetch result to ensure query actually executed
            row = result.fetchone()
            logger.info(f"Test query result: {row}")
            
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        logger.error(f"Error type: {type(e).__name__}")
        raise

# Run connection test
test_connection()

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency to get database session
def get_db():
    """
    Database session dependency for FastAPI
    """
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error: {e}")
        db.rollback()
        raise
    finally:
        db.close()

# Function to create all tables
def create_tables():
    """
    Create all database tables
    """
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise

# Function to drop all tables (use with caution)
def drop_tables():
    """
    Drop all database tables - USE WITH CAUTION
    """
    try:
        Base.metadata.drop_all(bind=engine)
        logger.info("Database tables dropped successfully")
    except Exception as e:
        logger.error(f"Failed to drop database tables: {e}")
        raise

# Health check function
def check_db_health():
    """
    Check database health
    """
    try:
        with engine.connect() as conn:
            if HAS_TEXT:
                conn.execute(text("SELECT 1"))
            else:
                conn.execute("SELECT 1")
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False

# Function to execute raw SQL safely
def execute_raw_sql(sql_query, params=None):
    """
    Execute raw SQL query safely with version compatibility
    """
    try:
        with engine.connect() as conn:
            if HAS_TEXT:
                if params:
                    result = conn.execute(text(sql_query), params)
                else:
                    result = conn.execute(text(sql_query))
            else:
                if params:
                    result = conn.execute(sql_query, params)
                else:
                    result = conn.execute(sql_query)
            return result
    except Exception as e:
        logger.error(f"Failed to execute SQL query: {e}")
        raise