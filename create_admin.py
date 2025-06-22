import getpass
from sqlalchemy.orm import Session
from database import SessionLocal, engine
import models
from auth import get_password_hash

def create_admin_user():
    """
    A command-line script to create an initial admin user for the application.
    """
    print("--- Create Admin User ---")
    
    # Establish a database session
    db: Session = SessionLocal()
    
    try:
        # Get user input
        full_name = input("Enter admin's full name: ").strip()
        email = input("Enter admin's email address: ").strip()
        
        # Check if the user already exists
        existing_user = db.query(models.User).filter(models.User.email == email).first()
        if existing_user:
            print(f"\nError: A user with the email '{email}' already exists.")
            # Ask if the user wants to promote them
            promote = input(f"Do you want to promote this user to an admin? (y/n): ").lower()
            if promote == 'y':
                existing_user.role = 'admin'
                db.commit()
                print(f"Success! User '{email}' has been promoted to an admin.")
            return

        # Get password securely
        password = getpass.getpass("Enter a password for the admin: ")
        password_confirm = getpass.getpass("Confirm the password: ")

        if password != password_confirm:
            print("\nError: Passwords do not match. Please try again.")
            return

        if not all([full_name, email, password]):
            print("\nError: Full name, email, and password cannot be empty.")
            return

        # Create the new admin user
        hashed_password = get_password_hash(password)
        admin_user = models.User(
            full_name=full_name,
            email=email,
            hashed_password=hashed_password,
            role='admin'  # Set the role directly to 'admin'
        )
        
        db.add(admin_user)
        db.commit()
        
        print(f"\nSuccess! Admin user '{full_name}' with email '{email}' created.")

    finally:
        db.close()

if __name__ == "__main__":
    # Create the database tables if they don't exist
    models.Base.metadata.create_all(bind=engine)
    create_admin_user()
