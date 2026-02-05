import os
import uuid
import smtplib
import secrets
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import FastAPI, HTTPException, Request, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field, field_validator
from pydantic import Field
import re
from supabase import create_client
from dotenv import load_dotenv
from fastapi import Body
from datetime import datetime, timedelta
from datetime import datetime, date
from datetime import datetime, timezone
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from fastapi.responses import FileResponse
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import uuid
from fastapi import Header
from typing import Optional


load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
# Service role key bypasses RLS - use for admin operations
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", SUPABASE_KEY)

# Email configuration (Gmail SMTP)
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

# Frontend URL for redirects
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

# Backend URL for verification links
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

# SMS configuration (Twilio)
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
# Admin client with service role key (bypasses RLS)
supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

app = FastAPI(
    title="Animal Farm API",
    description="Authentication system for Farm Booking",
    version="1.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Frontend URL
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)

# Exception handler for request validation errors
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle FastAPI validation errors with better error messages"""
    errors = exc.errors()
    error_details = []
    
    for error in errors:
        field = ".".join(str(loc) for loc in error["loc"])
        error_type = error["type"]
        error_msg = error.get("msg", "Validation error")
        
        if error_type == "value_error.missing":
            error_details.append(f"Missing required field: {field}")
        elif error_type == "type_error.str":
            error_details.append(f"Field '{field}' must be a string")
        else:
            error_details.append(f"Field '{field}': {error_msg}")
    
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "detail": "; ".join(error_details) if error_details else "Invalid request data"
        }
    )

@app.get("/")
def root():
    return {
        "status": "success",
        "message": "Animal Farm API is running",
        "docs": "/docs",
        "health": "OK"
    }

# -------------------------
# Request Body
# -------------------------
class SignupRequest(BaseModel):
    name: str = Field(..., min_length=1, description="User's full name")
    email: str = Field(..., min_length=1, description="User's email address")
    phone: str = Field(..., min_length=1, description="User's phone number")
    password: str = Field(..., min_length=6, description="User's password (minimum 6 characters)")
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v: str) -> str:
        """Validate email format"""
        if not v or not v.strip():
            raise ValueError("Email is required")
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, v.strip()):
            raise ValueError("Please provide a valid email address")
        return v.strip()
    
    class Config:
        json_schema_extra = {
            "example": {
                "name": "John Doe",
                "email": "john.doe@example.com",
                "phone": "+1234567890",
                "password": "securepassword123"
            }
        }

class LoginRequest(BaseModel):
    login: str   # email OR phone
    password: str

class ForgotPasswordRequest(BaseModel):
    login: str   # email OR phone


class DirectResetRequest(BaseModel):
    user_id: str
    new_password: str
    
    class Config:
        # Better error messages for missing fields
        schema_extra = {
            "example": {
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "new_password": "newSecurePassword123"
            }
        }

# -------------------------
# Email and SMS Helper Functions
# -------------------------
def send_welcome_email(email: str, name: str):
    """Send welcome email to user after successful account creation"""
    try:
        if not SMTP_EMAIL or not SMTP_PASSWORD:
            print("Warning: Email credentials not configured. Skipping email send.")
            return
        
        message = MIMEMultipart("alternative")
        message["Subject"] = "Welcome to Animal Farm!"
        message["From"] = SMTP_EMAIL
        message["To"] = email
        
        # Email body
        text = f"""
Dear {name},

Your account has been successfully created. Welcome to Animal Farm!

We're excited to have you join our community.

Best regards,
Animal Farm Team
        """
        
        html = f"""
<html>
  <body>
    <h2>Welcome to Animal Farm, {name}!</h2>
    <p>Your account has been successfully created. Welcome to Animal Farm!</p>
    <p>We're excited to have you join our community.</p>
    <br>
    <p>Best regards,<br>Animal Farm Team</p>
  </body>
</html>
        """
        
        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")
        
        message.attach(part1)
        message.attach(part2)
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, email, message.as_string())
        
        print(f"Welcome email sent successfully to {email}")
    except Exception as e:
        print(f"Error sending welcome email to {email}: {str(e)}")


def send_verification_email(email: str, name: str, verification_token: str):
    """Send email verification link to user after signup"""
    try:
        if not SMTP_EMAIL or not SMTP_PASSWORD:
            print("Warning: Email credentials not configured. Skipping verification email send.")
            return
        
        verification_link = f"{BACKEND_URL}/verify-email?token={verification_token}"
        
        message = MIMEMultipart("alternative")
        message["Subject"] = "Verify Your Email - Animal Farm"
        message["From"] = SMTP_EMAIL
        message["To"] = email
        
        # Email body
        text = f"""
Dear {name},

Welcome to Animal Farm! Please verify your email address to complete your registration.

Click the link below to verify your email:
{verification_link}

If the link doesn't work, copy and paste it into your browser.

This link will expire in 24 hours.

Best regards,
Animal Farm Team
        """
        
        html = f"""
<html>
  <body>
    <h2>Welcome to Animal Farm, {name}!</h2>
    <p>Please verify your email address to complete your registration.</p>
    <p>
      <a href="{verification_link}" style="background-color: #4CAF50; color: white; padding: 14px 20px; text-decoration: none; display: inline-block; border-radius: 4px;">
        Verify Email Address
      </a>
    </p>
    <p>Or copy and paste this link into your browser:</p>
    <p style="word-break: break-all; color: #666;">{verification_link}</p>
    <p style="color: #999; font-size: 12px;">This link will expire in 24 hours.</p>
    <br>
    <p>Best regards,<br>Animal Farm Team</p>
  </body>
</html>
        """
        
        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")
        
        message.attach(part1)
        message.attach(part2)
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, email, message.as_string())
        
        print(f"Verification email sent successfully to {email}")
    except Exception as e:
        print(f"Error sending verification email to {email}: {str(e)}")


def send_welcome_sms(phone: str, name: str):
    """Send welcome SMS to user after successful account creation"""
    try:
        if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN or not TWILIO_PHONE_NUMBER:
            print("Warning: Twilio credentials not configured. Skipping SMS send.")
            return
        
        from twilio.rest import Client
        
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        
        message_body = f"Your account has been successfully created. Welcome to Animal Farm! - Animal Farm Team"
        
        message = client.messages.create(
            body=message_body,
            from_=TWILIO_PHONE_NUMBER,
            to=phone
        )
        
        print(f"Welcome SMS sent successfully to {phone}. Message SID: {message.sid}")
    except ImportError:
        print("Warning: Twilio package not installed. Skipping SMS send.")
    except Exception as e:
        print(f"Error sending welcome SMS to {phone}: {str(e)}")


# -------------------------
# Signup API
# -------------------------
@app.post("/signup", tags=["Authentication"])
def signup(data: SignupRequest, background_tasks: BackgroundTasks):
    try:
        # Validate input
        if not data.email or not data.email.strip():
            raise HTTPException(status_code=400, detail="Email is required")
        if not data.password or len(data.password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters long")
        if not data.name or not data.name.strip():
            raise HTTPException(status_code=400, detail="Name is required")
        if not data.phone or not data.phone.strip():
            raise HTTPException(status_code=400, detail="Phone number is required")
        
        # Check if user already exists (by email) in profiles table (active accounts only)
        existing_user = supabase.table("profiles").select("email, id").eq("email", data.email.strip()).execute()
        if len(existing_user.data) > 0:
            raise HTTPException(status_code=400, detail="An account with this email already exists")
        
        # Check if phone number already exists in profiles table
        existing_phone = supabase.table("profiles").select("phone, id").eq("phone", data.phone.strip()).execute()
        if len(existing_phone.data) > 0:
            raise HTTPException(status_code=400, detail="An account with this phone number already exists")

        # We Create user in Supabase Auth
        try:
            auth_response = supabase.auth.admin.create_user({
                "email": data.email.strip(),
                "password": data.password,
                "email_confirm": False
            })
            
            if not auth_response or not auth_response.user:
                raise HTTPException(status_code=400, detail="Failed to create user account. Please try again.")
            
            user = auth_response.user
        except Exception as auth_error:
            error_message = str(auth_error).lower()
            
            # Handle "user already registered" - might be a deleted user trying to recreate account
            if "user already registered" in error_message or "already registered" in error_message or "duplicate" in error_message:
                try:
                    # Try to find and delete any existing auth user with this email
                    # Search through users to find one with matching email (handle pagination)
                    existing_auth_user = None
                    page = 1
                    per_page = 50
                    
                    try:
                        # Search through paginated users
                        while existing_auth_user is None:
                            users_list = supabase.auth.admin.list_users(page=page, per_page=per_page)
                            
                            # Handle different return types (list vs object with .users attribute)
                            users_to_search = []
                            if isinstance(users_list, list):
                                users_to_search = users_list
                            elif hasattr(users_list, 'users'):
                                users_to_search = users_list.users
                            elif hasattr(users_list, '__iter__'):
                                users_to_search = list(users_list)
                            else:
                                break
                            
                            if not users_to_search or len(users_to_search) == 0:
                                break  # No more users to check
                            
                            # Search through users to find one with matching email
                            for u in users_to_search:
                                user_email = getattr(u, 'email', None) if hasattr(u, 'email') else (u.get('email') if isinstance(u, dict) else None)
                                if user_email and user_email.lower() == data.email.strip().lower():
                                    existing_auth_user = u
                                    break
                            
                            # If we didn't find it and got less than per_page results, no more pages
                            if len(users_to_search) < per_page:
                                break
                            
                            page += 1
                            # Safety limit to avoid infinite loops
                            if page > 100:
                                break
                        
                        # If found, permanently delete it (hard delete)
                        if existing_auth_user:
                            try:
                                # Extract user ID from different object types
                                user_id = None
                                if hasattr(existing_auth_user, 'id'):
                                    user_id = existing_auth_user.id
                                elif isinstance(existing_auth_user, dict) and 'id' in existing_auth_user:
                                    user_id = existing_auth_user['id']
                                
                                if user_id:
                                    supabase.auth.admin.delete_user(user_id, should_soft_delete=False)
                                    print(f"Deleted existing auth user {user_id} for email {data.email.strip()}")
                            except Exception as delete_error:
                                print(f"Error deleting existing auth user: {delete_error}")
                                # Continue anyway, might work on retry
                        
                        # Also check and delete any orphaned profile with this email
                        orphaned_profiles = supabase.table("profiles").select("id").eq("email", data.email.strip()).execute()
                        for profile in orphaned_profiles.data:
                            try:
                                supabase.table("profiles").delete().eq("id", profile["id"]).execute()
                                print(f"Deleted orphaned profile {profile['id']} for email {data.email.strip()}")
                            except:
                                pass
                        
                        # Retry creating the user
                        auth_response = supabase.auth.admin.create_user({
                            "email": data.email.strip(),
                            "password": data.password,
                            "email_confirm": False
                        })
                        
                        if not auth_response or not auth_response.user:
                            raise HTTPException(status_code=400, detail="Failed to create user account. Please try again.")
                        
                        user = auth_response.user
                    except Exception as retry_error:
                        print(f"Error during cleanup and retry: {retry_error}")
                        raise HTTPException(
                            status_code=400, 
                            detail="An account with this email already exists. If you recently deleted your account, please wait a few moments and try again."
                        )
                except Exception as cleanup_error:
                    print(f"Error cleaning up existing user: {cleanup_error}")
                    raise HTTPException(
                        status_code=400, 
                        detail="An account with this email already exists. If you recently deleted your account, please wait a few moments and try again."
                    )
            elif "invalid email" in error_message or ("email" in error_message and "invalid" in error_message):
                raise HTTPException(status_code=400, detail="Please provide a valid email address")
            elif "password" in error_message and ("weak" in error_message or "short" in error_message):
                raise HTTPException(status_code=400, detail="Password is too weak. Please choose a stronger password.")
            elif "not_admin" in error_message or "unauthorized" in error_message:
                raise HTTPException(status_code=500, detail="Server configuration error. Please contact support.")
            else:
                # Log the actual error for debugging
                print(f"Supabase auth error: {auth_error}")
                raise HTTPException(status_code=400, detail="Failed to create user account. Please check your information and try again.")

        # Store extra info in profiles table
        try:
            profile = {
                "id": user.id,
                "name": data.name.strip(),
                "phone": data.phone.strip(),
                "email": data.email.strip()
            }

            profile_result = supabase.table("profiles").insert(profile).execute()
            
            if not profile_result.data:
                # If profile insert fails, we should clean up the auth user
                try:
                    supabase.auth.admin.delete_user(user.id)
                except:
                    pass
                raise HTTPException(status_code=400, detail="Failed to create user profile. Please try again.")
                
        except Exception as profile_error:
            error_message = str(profile_error).lower()
            
            # Clean up auth user if profile creation fails
            try:
                supabase.auth.admin.delete_user(user.id)
            except:
                pass
            
            if "duplicate" in error_message or "unique" in error_message or "already exists" in error_message:
                raise HTTPException(status_code=400, detail="An account with this email or phone number already exists")
            elif "foreign key" in error_message:
                raise HTTPException(status_code=400, detail="Invalid user data. Please try again.")
            else:
                print(f"Profile insert error: {profile_error}")
                raise HTTPException(status_code=400, detail="Failed to create user profile. Please try again.")

        # Generate verification token
        verification_token = secrets.token_urlsafe(32)
        # Embed user_id in token format: {token}::{user_id}
        verification_token_with_id = f"{verification_token}::{user.id}"
        
        # Send verification email in background
        background_tasks.add_task(send_verification_email, data.email.strip(), data.name.strip(), verification_token_with_id)

        return {
            "status": "success",
            "message": "User created successfully. Please check your email to verify your account.",
            "user_id": user.id
        }

    except HTTPException:
        raise
    except Exception as e:
        # Catch any unexpected errors
        print(f"Unexpected signup error: {e}")
        raise HTTPException(status_code=400, detail="An error occurred while creating your account. Please try again.")


# -------------------------
# Email Verification API
# -------------------------
@app.get("/verify-email", tags=["Authentication"])
async def verify_email(token: str):
    """
    Verify user email address using token from verification link.
    Redirects to login page after successful verification.
    """
    try:
        if not token:
            # Redirect to login with error parameter
            return RedirectResponse(url=f"{FRONTEND_URL}/login?error=invalid_token", status_code=302)
        
        # Parse token (format: {token}::{user_id})
        if "::" not in token:
            return RedirectResponse(url=f"{FRONTEND_URL}/login?error=invalid_token", status_code=302)
        
        token_parts = token.split("::")
        if len(token_parts) != 2:
            return RedirectResponse(url=f"{FRONTEND_URL}/login?error=invalid_token", status_code=302)
        
        verification_token = token_parts[0]
        user_id = token_parts[1]
        
        # Validate user_id is a valid UUID
        try:
            uuid.UUID(user_id)
        except (ValueError, AttributeError):
            return RedirectResponse(url=f"{FRONTEND_URL}/login?error=invalid_token", status_code=302)
        
        # Verify user exists in profiles table
        profile_result = supabase.table("profiles").select("id, email").eq("id", user_id).execute()
        
        if len(profile_result.data) == 0:
            return RedirectResponse(url=f"{FRONTEND_URL}/login?error=user_not_found", status_code=302)
        
        # Confirm the user's email using Supabase admin API
        try:
            supabase.auth.admin.update_user_by_id(
                user_id,
                {"email_confirm": True}
            )
            
            print(f"Email verified successfully for user {user_id}")
            
            # Redirect to login page with success message
            return RedirectResponse(url=f"{FRONTEND_URL}/login?verified=true", status_code=302)
        
        except Exception as verify_error:
            error_message = str(verify_error).lower()
            print(f"Error verifying email: {verify_error}")
            
            if "user_not_found" in error_message or "user not found" in error_message:
                return RedirectResponse(url=f"{FRONTEND_URL}/login?error=user_not_found", status_code=302)
            else:
                return RedirectResponse(url=f"{FRONTEND_URL}/login?error=verification_failed", status_code=302)
    
    except Exception as e:
        print(f"Unexpected verification error: {e}")
        return RedirectResponse(url=f"{FRONTEND_URL}/login?error=verification_failed", status_code=302)


# -------------------------
# Login API
# -------------------------
@app.post("/login", tags=["Authentication"])
def login_email_or_Phone_no(data: LoginRequest):

    try:
        email = data.login

        # If phone number entered → find email from profiles table
        if "@" not in data.login:
            result = supabase.table("profiles").select("email").eq("phone", data.login).execute()

            if len(result.data) == 0:
                raise HTTPException(status_code=400, detail="Phone number not found")

            email = result.data[0]["email"]

        # First, verify user exists in profiles table
        profile_result = supabase.table("profiles").select("id").eq("email", email).execute()
        
        if len(profile_result.data) == 0:
            raise HTTPException(status_code=401, detail="Invalid login credentials")

        user_id = profile_result.data[0]["id"]

        # Try to login with password
        try:
            auth = supabase.auth.sign_in_with_password({
                "email": email,
                "password": data.password
            })
            user = auth.user
            session = auth.session

        except Exception as auth_error:
            error_str = str(auth_error).lower()
            
            # Handle "User not allowed" error - usually means email not confirmed
            if "user not allowed" in error_str or "email not confirmed" in error_str or "email_address_not_authorized" in error_str:
                raise HTTPException(
                    status_code=401, 
                    detail="Please verify your email address before logging in. Check your inbox for the verification link."
                )
            else:
                # Other authentication errors (wrong password, etc.)
                raise HTTPException(status_code=401, detail="Invalid login credentials")

        # Get user profile
        profile = supabase.table("profiles").select("*").eq("id", user.id).execute()

        if len(profile.data) == 0:
            raise HTTPException(status_code=404, detail="User profile not found")

        return {
             "status": "success",
            "access_token": session.access_token,
            "user": profile.data[0],
            "role": profile.data[0]["role"] if "role" in profile.data[0] else "user"
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid login credentials")

# -------------------------
# Logout API
# ------------------------- 
class LogoutRequest(BaseModel):
    access_token: str

@app.post("/logout", tags=["Authentication"])
def logout(data: LogoutRequest):
    try:
        supabase.auth.sign_out(data.access_token)
        return {"status": "success", "message": "Logged out successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Logout failed")


# -------------------------
# Forgot Password API
# -------------------------
@app.post("/forgot-password", tags=["Authentication"])
def forgot_password(data: ForgotPasswordRequest):

    # 1. Find user
    if "@" in data.login:
        res = supabase_admin.table("profiles").select("id, email").eq("email", data.login).execute()
    else:
        res = supabase_admin.table("profiles").select("id, email").eq("phone", data.login).execute()

    if not res.data:
        # Don't reveal if account exists (security)
        return {"status": "ok", "message": "If account exists, reset link has been sent"}

    user = res.data[0]

    # 2. Generate secure token
    token = secrets.token_urlsafe(32)

    expires_at = (datetime.utcnow() + timedelta(minutes=30)).isoformat()

    # 3. Store token
    supabase_admin.table("password_reset_tokens").insert({
        "user_id": user["id"],
        "token": token,
        "expires_at": expires_at
    }).execute()

    # 4. Send email
    reset_link = f"{FRONTEND_URL}/reset-password?token={token}"

    send_email(
        user["email"],
        "Reset Your Animal Farm Password",
        f"""
        <h3>Reset Password</h3>
        <p>Click the link below to reset your password:</p>
        <a href="{reset_link}">{reset_link}</a>
        <p>This link is valid for 30 minutes.</p>
        """
    )

    return {"status": "ok", "message": "If account exists, reset link has been sent"}

# -------------------------
# Reset Password API
# -------------------------
class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


@app.post("/reset-password", tags=["Authentication"])
def reset_password(data: ResetPasswordRequest):

    try:
        # Validate input
        if not data.token or not data.new_password:
            raise HTTPException(status_code=400, detail="Token and password are required")

        if len(data.new_password) < 6:
            raise HTTPException(
                status_code=400,
                detail="Password must be at least 6 characters long"
            )

        # 🔍 Find valid token
        token_res = (
            supabase
            .table("password_reset_tokens")
            .select("id, user_id, expires_at, used")
            .eq("token", data.token)
            .execute()
        )

        if not token_res.data:
            raise HTTPException(
                status_code=400,
                detail="Invalid or expired reset token"
            )

        token_row = token_res.data[0]

        # Check if already used
        if token_row["used"]:
            raise HTTPException(
                status_code=400,
                detail="Reset link already used"
            )

        # Check expiry
        if datetime.now(timezone.utc) > datetime.fromisoformat(token_row["expires_at"]):
            raise HTTPException(
                status_code=400,
                detail="Reset link has expired"
            )

        user_id = token_row["user_id"]

        # 🔐 Update password (ADMIN API → service role key REQUIRED)
        supabase.auth.admin.update_user_by_id(
            user_id,
            {"password": data.new_password}
        )

        # ✅ Mark token as used
        supabase.table("password_reset_tokens").update(
            {"used": True}
        ).eq("id", token_row["id"]).execute()

        return {
            "status": "success",
            "message": "Password reset successful. You can now login."
        }

    except HTTPException:
        raise

    except Exception as e:
        print("RESET PASSWORD ERROR 👉", e)
        raise HTTPException(
            status_code=500,
            detail="Unable to reset password. Please try again."
        )
# -------------------------
# Create Booking Type API
# -------------------------
class BookingTypeRequest(BaseModel):
    name: str
    description: str
    adult_price: float
    child_price: float
    total_capacity: int = Field(gt=0, description="Max people per day")
    admin_id: str
    features: list[str] =[]

@app.post("/admin/booking-type", tags=["Admin"])
def create_booking_type(data: BookingTypeRequest):
    # Use admin client to bypass RLS policies
    return supabase_admin.table("booking_types").insert({
    "name": data.name,
    "description": data.description,
    "adult_price": data.adult_price,
    "child_price": data.child_price,
    "total_capacity": data.total_capacity,
    "features": data.features,
    "created_by": data.admin_id
}).execute()

# -------------------------
# Edit Booking Type API
# -------------------------
class PartialUpdateBookingTypeRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    adult_price: Optional[float] = None
    child_price: Optional[float] = None
    total_capacity: Optional[int] = Field(default=None, gt=0)
    is_active: Optional[bool] = None


@app.patch("/admin/booking-type/{booking_type_id}", tags=["Admin"])
def partial_update_booking_type(
    booking_type_id: str,
    data: PartialUpdateBookingTypeRequest
):
    # 1️⃣ Existing booking type fetch करा
    existing_res = (
        supabase_admin
        .table("booking_types")
        .select("*")
        .eq("id", booking_type_id)
        .execute()
    )

    if not existing_res.data:
        raise HTTPException(status_code=404, detail="Booking type not found")

    existing = existing_res.data[0]

    # 2️⃣ Incoming data
    incoming = data.dict(exclude_unset=True)

    update_data = {}

    # 3️⃣ Compare each field
    for field, new_value in incoming.items():

        # empty string ignore
        if isinstance(new_value, str) and new_value.strip() == "":
            continue

        # None ignore
        if new_value is None:
            continue

        old_value = existing.get(field)

        # 4️⃣ Only update if value is actually changed
        if new_value != old_value:
            update_data[field] = new_value

    if not update_data:
        return {
            "status": "success",
            "message": "No changes detected"
        }

    # 5️⃣ Update only changed fields
    supabase_admin.table("booking_types") \
        .update(update_data) \
        .eq("id", booking_type_id) \
        .execute()

    return {
        "status": "success",
        "message": "Booking type updated successfully",
        "updated_fields": list(update_data.keys())
    }



# -------------------------
# Create Time Slot API
# -------------------------
@app.get("/booking-types", tags=["User"])
def get_booking_types():
    return supabase.table("booking_types") \
        .select(
            "id, name, description, adult_price, child_price, total_capacity"
        ) \
        .eq("is_active", True) \
        .execute()


class TimeSlotRequest(BaseModel):
    booking_type_id: str
    slot_name: str
    start_time: str
    end_time: str
    capacity: int


@app.get("/time-slots/{booking_type_id}", tags=["User"])
def get_time_slots(booking_type_id: str):
    return supabase.table("time_slots") \
        .select("id, slot_name, start_time, end_time, capacity") \
        .eq("booking_type_id", booking_type_id) \
        .eq("is_active", True) \
        .execute()

# -------------------------
# Create Time Slot API
# -------------------------
@app.post("/admin/time-slot", tags=["Admin"])
def create_time_slot(data: TimeSlotRequest):
    # Use admin client to bypass RLS policies
    return supabase_admin.table("time_slots").insert({
        "booking_type_id": data.booking_type_id,
          "slot_name": data.slot_name,
        "start_time": data.start_time,
        "end_time": data.end_time,
        "capacity": data.capacity,
        "is_active": True
    }).execute()

# -------------------------
# Admin Update Booking Type API
# -------------------------
class UpdateBookingTypeRequest(BaseModel):
    name: str
    description: str
    adult_price: float
    child_price: float
    total_capacity: int = Field(gt=0)
    is_active: bool

@app.put("/admin/booking-type/{booking_type_id}", tags=["Admin"])
def update_booking_type(booking_type_id: str, data: UpdateBookingTypeRequest):
    return supabase_admin.table("booking_types") \
        .update({
            "name": data.name,
            "description": data.description,
            "adult_price": data.adult_price,
            "child_price": data.child_price,
            "total_capacity": data.total_capacity,
            "is_active": data.is_active
        }) \
        .eq("id", booking_type_id) \
        .execute()
# -------------------------
# Create Time Slot API
# -------------------------
@app.get("/admin/booking-types", tags=["Admin"])
def get_admin_booking_types():
    return supabase_admin.table("booking_types") \
        .select(
            "id, name, description, adult_price, child_price, total_capacity, is_active"
        ) \
        .execute()

# -------------------------
# Admin Enable/Disable Booking Type API
# -------------------------
@app.post("/admin/booking-type/{booking_type_id}/toggle", tags=["Admin"])
def toggle_booking_type(booking_type_id: str, is_active: bool):
    # Use admin client to bypass RLS policies
    return supabase_admin.table("booking_types") \
        .update({"is_active": is_active}) \
        .eq("id", booking_type_id) \
        .execute()

# -------------------------
# User Book Ticket API
# -------------------------
class BookingRequest(BaseModel):
    user_id: str
    booking_type_id: str
    time_slot_id: str
    visit_date: date

    adults: int
    children: int
    addons: list[str] = []

    contact_name: str
    contact_email: str
    contact_phone: str

    preferred_contact: str | None = "email"
    notes: str | None = None


# -------------------------
# Admin Addons API
# -------------------------
class PriceRequest(BaseModel):
    booking_type_id: str
    adults: int
    children: int
    addons: list[str] 

class UpdateAddonRequest(BaseModel):
    price: Optional[float] = Field(None, gt=0)
    name: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    is_active: Optional[bool] = None 


@app.post("/admin/addon", tags=["Admin"])
def create_addon(name: str, description: str, price: float):
    # Use admin client to bypass RLS policies
    return supabase_admin.table("addons").insert({
        "name": name,
        "description": description,
        "price": price,
        "is_active": True 
    }).execute()


@app.get("/addons", tags=["User"])
def get_addons():
    return supabase.table("addons") \
        .select("*") \
        .eq("is_active", True) \
        .execute()


@app.patch("/admin/addon/{addon_id}/toggle", tags=["Admin"])
def toggle_addon(addon_id: str, is_active: bool):

    addon = supabase_admin.table("addons") \
        .select("id") \
        .eq("id", addon_id) \
        .execute()

    if not addon.data:
        raise HTTPException(status_code=404, detail="Addon not found")

    supabase_admin.table("addons") \
        .update({"is_active": is_active}) \
        .eq("id", addon_id) \
        .execute()

    return {
        "status": "success",
        "message": f"Addon {'activated' if is_active else 'deactivated'}"
    }

# -------------------------
# Admin Edit Addons perticular field API
# ------------------------- 
@app.patch("/admin/addon/{addon_id}", tags=["Admin"])
def update_addon(addon_id: str, data: UpdateAddonRequest):

    # 1️⃣ Existing addon fetch
    existing_res = (
        supabase_admin
        .table("addons")
        .select("*")
        .eq("id", addon_id)
        .execute()
    )

    if not existing_res.data:
        raise HTTPException(status_code=404, detail="Addon not found")

    existing = existing_res.data[0]

    # 2️⃣ Incoming data (only fields sent)
    incoming = data.dict(exclude_unset=True)

    update_data = {}

    # 3️⃣ Compare field by field
    for field, new_value in incoming.items():

        # ignore None
        if new_value is None:
            continue

        # ignore empty strings
        if isinstance(new_value, str) and new_value.strip() == "":
            continue

        old_value = existing.get(field)

        # 4️⃣ Update only if value actually changed
        if new_value != old_value:
            update_data[field] = new_value

    # 5️⃣ Nothing changed
    if not update_data:
        return {
            "status": "success",
            "message": "No changes detected"
        }

    # 6️⃣ Update only changed fields
    supabase_admin.table("addons") \
        .update(update_data) \
        .eq("id", addon_id) \
        .execute()

    return {
        "status": "success",
        "message": "Addon updated successfully",
        "updated_fields": list(update_data.keys())
    }

# -------------------------
# Counter Booking API
# ------------------------- 
@app.post("/admin/book-walkin", tags=["Admin"])
def admin_book_walkin(data: BookingRequest):

    # 1. create fake user / walkin user
    user = supabase_admin.table("walkin_customers").insert({
        "name": data.contact_name,
        "phone": data.contact_phone,
        "email": data.contact_email
    }).execute().data[0]

    # 2. create booking using same RPC
    res = supabase_admin.rpc("create_booking_safe", {
        "p_user_id": user["id"],   # fake user
    }).execute()

    return {"status": "success"}

# -------------------------
# User Add Addons to Booking API
# -------------------------
class BookingAddonRequest(BaseModel):
    booking_id: str
    addon_ids: list[str]

@app.post("/booking/addons", tags=["User"])
def add_addons_to_booking(data: BookingAddonRequest):
    # Validate that the booking exists
    booking_check = supabase.table("bookings") \
        .select("id") \
        .eq("id", data.booking_id) \
        .execute()
    
    if not booking_check.data:
        raise HTTPException(
            status_code=404, 
            detail=f"Booking with ID {data.booking_id} not found"
        )
    
    # Validate that all addon_ids exist (if addons are provided)
    if data.addon_ids:
        addons_check = supabase.table("addons") \
            .select("id") \
            .in_("id", data.addon_ids) \
            .execute()
        
        existing_addon_ids = {addon["id"] for addon in addons_check.data}
        missing_addon_ids = set(data.addon_ids) - existing_addon_ids
        
        if missing_addon_ids:
            raise HTTPException(
                status_code=404,
                detail=f"Addons not found: {', '.join(missing_addon_ids)}"
            )
    
    # Delete previous addons (if user edits)
    supabase.table("booking_addons") \
        .delete() \
        .eq("booking_id", data.booking_id) \
        .execute()

    # Insert new addons
    if data.addon_ids:
        for addon_id in data.addon_ids:
            supabase.table("booking_addons").insert({
                "booking_id": data.booking_id,
                "addon_id": addon_id
            }).execute()

    return {"status": "success", "message": "Addons added to booking"}

# -------------------------
# User Calculate Price API
# -------------------------  
def calculate_price_internal(
    booking_type_id: str,
    adults: int,
    children: int,
    addons: list[str]
) -> dict:

    booking_type_result = supabase.table("booking_types") \
        .select("adult_price, child_price") \
        .eq("id", booking_type_id) \
        .execute()

    if not booking_type_result.data:
        raise HTTPException(status_code=404, detail="Booking type not found")

    bt = booking_type_result.data[0]

    base = (adults * bt["adult_price"]) + (children * bt["child_price"])

    addon_total = 0
    if addons:
        addons_result = supabase.table("addons") \
            .select("id, price") \
            .in_("id", addons) \
            .eq("is_active", True) \
            .execute()

        addon_total = sum(a["price"] for a in addons_result.data)

    return {
        "base_price": base,
        "addon_total": addon_total,
        "total": base + addon_total
    }
 
@app.post("/calculate-price", tags=["User"])
def calculate_price(data: PriceRequest):
    return calculate_price_internal(
        data.booking_type_id,
        data.adults,
        data.children,
        data.addons
    )
    
    # Validate that booking type exists
    if not booking_type_result.data:
        raise HTTPException(
            status_code=404,
            detail=f"Booking type with ID {data.booking_type_id} not found. Please verify the booking type ID is correct."
        )
    
    bt = booking_type_result.data[0]
    
    # Warn if booking type is inactive (but still allow price calculation)
    if not bt.get("is_active", True):
        pass

    base = (data.adults * bt["adult_price"]) + (data.children * bt["child_price"])

    addon_total = 0
    if data.addons:
        addons_result = supabase.table("addons") \
            .select("id, price") \
            .in_("id", data.addons) \
            .execute()
        
        addons = addons_result.data
        
        # Validate that all addons exist
        existing_addon_ids = {addon["id"] for addon in addons} if addons else set()
        missing_addon_ids = set(data.addons) - existing_addon_ids
        
        if missing_addon_ids:
            raise HTTPException(
                status_code=404,
                detail=f"Addons not found: {', '.join(missing_addon_ids)}"
            )

        for a in addons:
            addon_total += a["price"]

    return {
        "base_price": base,
        "addon_total": addon_total,
        "total": base + addon_total
    }

# -------------------------
# Admin Show All Bookings API
# -------------------------
# @app.post("/book", tags=["User"])
# def create_booking(data: BookingRequest):

#     # 💰 Calculate price FIRST
#     price = calculate_price_internal(
#         data.booking_type_id,
#         data.adults,
#         data.children,
#         data.addons
#     )

#     total_amount = price["total"]

#     try:
#         res = supabase_admin.rpc(
#             "create_booking_safe",
#             {
#                 "p_user_id": data.user_id,
#                 "p_booking_type_id": data.booking_type_id,
#                 "p_time_slot_id": data.time_slot_id,
#                 "p_visit_date": data.visit_date.isoformat(),
#                 "p_adults": data.adults,
#                 "p_children": data.children,
#                 "p_total_amount": total_amount,   # ✅ HERE
#                 "p_contact_name": data.contact_name,
#                 "p_contact_email": data.contact_email,
#                 "p_contact_phone": data.contact_phone,
#                 "p_preferred_contact": data.preferred_contact,
#                 "p_notes": data.notes
#             }
#         ).execute()

#         booking_id = res.data

#         return {
#             "status": "success",
#             "booking_id": booking_id,
#             "total_amount": total_amount,
#             "message": "Booking confirmed"
#         }

#     except Exception as e:
#         error_msg = str(e)

#         if "Slot full" in error_msg:
#             raise HTTPException(status_code=400, detail=error_msg)

#         raise HTTPException(status_code=500, detail="Unable to create booking")

@app.post("/book", tags=["User"])
def create_booking(data: BookingRequest):

    # 🔒 1. USER VALIDATION
    user_res = supabase.table("profiles") \
        .select("id") \
        .eq("id", data.user_id) \
        .execute()

    if not user_res.data:
        raise HTTPException(status_code=400, detail="Invalid user")

    # 🧹 2. SAFE ADDONS
    addons = data.addons or []

    # 💰 3. PRICE CALCULATION (SAFE)
    try:
        price = calculate_price_internal(
            data.booking_type_id,
            data.adults,
            data.children,
            addons
        )
    except Exception as e:
        print("PRICE ERROR 👉", e)
        raise HTTPException(status_code=400, detail="Invalid price data")

    # 📅 4. DATE SAFETY
    try:
        visit_date = data.visit_date.isoformat()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid visit date")

    # 🚀 5. BOOKING RPC
    try:
        res = supabase_admin.rpc(
            "create_booking_safe",
            {
                "p_user_id": data.user_id,
                "p_booking_type_id": data.booking_type_id,
                "p_time_slot_id": data.time_slot_id,
                "p_visit_date": visit_date,
                "p_adults": data.adults,
                "p_children": data.children,
                "p_total_amount": price["total"],
                "p_contact_name": data.contact_name,
                "p_contact_email": data.contact_email,
                "p_contact_phone": data.contact_phone,
                "p_preferred_contact": data.preferred_contact,
                "p_notes": data.notes
            }
        ).execute()

        if not res.data:
            raise Exception("RPC failed")

        return {
            "status": "success",
            "booking_id": res.data,
            "total_amount": price["total"]
        }

    except Exception as e:
        print("BOOKING ERROR 👉", e)
        raise HTTPException(status_code=500, detail=str(e))


# -------------------------
# Cash-received Bookings API
# -------------------------
@app.post("/admin/booking/{booking_id}/cash-received", tags=["Admin"])
def mark_cash_received(booking_id: str):

    # 1️⃣ Get booking details
    booking_res = supabase_admin.table("bookings") \
        .select("id, contact_name, contact_email, visit_date, total_amount, payment_received") \
        .eq("id", booking_id) \
        .execute()

    if not booking_res.data:
        raise HTTPException(status_code=404, detail="Booking not found")

    booking = booking_res.data[0]

    if booking["payment_received"]:
        return {
            "status": "already_done",
            "message": "Payment already marked as received"
        }

    # 2️⃣ Mark payment as received
    supabase_admin.table("bookings") \
        .update({"payment_received": True}) \
        .eq("id", booking_id) \
        .execute()

    # 3️⃣ Send payment received email
    email_body = payment_received_email_template(booking)
    send_email(booking["contact_email"], "Payment Received - Animal Farm", email_body)

    return {
        "status": "success",
        "message": "Cash marked as received and email sent"
    }


# -------------------------
# Admin Show User Bookings API
# -------------------------
@app.get("/admin/user-bookings/{user_id}", tags=["Admin"])
def get_user_bookings(user_id: str):

    return supabase.table("bookings") \
        .select(
            "id, visit_date, status, adults, children, booking_types(name), time_slots(slot_name,start_time,end_time), booking_addons(addons(name,price))"
        ) \
        .eq("user_id", user_id) \
        .execute()

# -------------------------
# Admin Show All Bookings API (ADMIN DASHBOARD LIST)
# -------------------------
@app.get("/admin/bookings", tags=["Admin"])
def admin_all_bookings():

    res = supabase_admin.table("bookings") \
        .select("""
            id,
            visit_date,
            status,
            adults,
            children,
            total_amount,
            payment_status,
            created_at,
            contact_name,
            contact_email,
            booking_types(name),
            time_slots(slot_name,start_time,end_time)
        """) \
        .order("created_at", desc=True) \
        .execute()

    return res.data

# -------------------------
# Admin Single Booking Details API (View Details Modal)
# -------------------------
@app.get("/admin/bookings/{booking_id}", tags=["Admin"])
def admin_booking_details(booking_id: str):

    res = supabase_admin.table("bookings") \
        .select("""
            id,
            visit_date,
            status,
            adults,
            children,
            total_amount,
            payment_status,
            payment_method,
            contact_name,
            contact_email,
            contact_phone,
            notes,
            booking_types(name),
            time_slots(slot_name,start_time,end_time)
        """) \
        .eq("id", booking_id) \
        .single() \
        .execute()

    if not res.data:
        raise HTTPException(status_code=404, detail="Booking not found")

    return res.data



# -------------------------
# Admin Show Stats API
# -------------------------
@app.get("/admin/stats", tags=["Admin"])
def admin_stats():

    today = supabase.rpc("count_bookings_today").execute().data
    week = supabase.rpc("count_bookings_week").execute().data
    month = supabase.rpc("count_bookings_month").execute().data
    year = supabase.rpc("count_bookings_year").execute().data

    return {
        "today": today,
        "this_week": week,
        "this_month": month,
        "this_year": year
    }

# -------------------------
# User Show My Bookings API
# -------------------------
@app.get("/my-bookings/{user_id}", tags=["User"])
def my_bookings(user_id: str):

    return supabase.table("bookings") \
        .select(
            "id,  visit_date,status,adults, children, total_amount,  contact_email,  contact_phone,   booking_types(name), time_slots(slot_name,start_time,end_time), booking_addons(addons(name,price))"
        ) \
        .eq("user_id", user_id) \
        .order("created_at", desc=True) \
        .execute()

# -------------------------
# Send Email Confirmation API
# -------------------------
def send_email(to_email: str, subject: str, body: str):
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        print("⚠️ Email credentials missing, skipping email")
        return

    msg = MIMEText(body, "html")
    msg["Subject"] = subject
    msg["From"] = SMTP_EMAIL
    msg["To"] = to_email

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.send_message(msg)  

# -------------------------
# Booking Done Email Template API
# -------------------------
def booking_email_template(data, booking):
    return f"""
    <h2>Booking Confirmed 🎉</h2>

    <p><b>Name:</b> {data.contact_name}</p>
    <p><b>Visit Date:</b> {data.visit_date}</p>
    <p><b>Time Slot:</b> {booking['time_slots']['slot_name']}
   ({booking['time_slots']['start_time']} - {booking['time_slots']['end_time']})</p>
    <p><b>Adults:</b> {data.adults}</p>
    <p><b>Children:</b> {data.children}</p>

    <hr/>

    <p><b>Total Amount:</b> ₹{booking['total_amount']}</p>
    <p><b>Payment Method:</b> Cash (Pay at counter)</p>

    <p><b>Booking ID:</b> {booking['id']}</p>

    <br/>
    <p>Please pay the above amount at the counter.</p>
    <p>Thank you for booking with <b>Animal Farm</b> 🐄🌿</p>
    """


# -------------------------
# Cancel Booking Email Template API
# -------------------------

def cancel_email_template(booking, user):
    return f"""
    <h2>Your Booking Has Been Cancelled ❌</h2>
    <p><b>Name:</b> {booking['contact_name']}</p>
    <p><b>Visit Date:</b> {booking['visit_date']}</p>
    <p><b>Booking ID:</b> {booking['id']}</p>
    <p>If this was a mistake, you can book again anytime.</p>
    """

# -------------------------
# Admin Cancel Booking API
# -------------------------    

@app.post("/admin/cancel-booking/{booking_id}", tags=["Admin"])
def cancel_booking(booking_id: str):

    booking = supabase.table("bookings") \
        .select("*, profiles(email)") \
        .eq("id", booking_id) \
        .execute().data[0]

    supabase.table("bookings") \
        .update({"status": "cancelled"}) \
        .eq("id", booking_id) \
        .execute()

    email_body = cancel_email_template(booking, booking["profiles"])

    send_email(booking["contact_email"], "Booking Cancelled", email_body)

    if booking["profiles"]["email"] != booking["contact_email"]:
        send_email(booking["profiles"]["email"], "Booking Cancelled", email_body)

    return {"status": "cancelled"}

# -------------------------
# User Cancel Booking API
# ------------------------- 
@app.post("/cancel-booking/{booking_id}", tags=["User"])
def user_cancel_booking(booking_id: str, user_id: str):

    booking_res = supabase.table("bookings") \
        .select("*, profiles(email)") \
        .eq("id", booking_id) \
        .execute()

    if not booking_res.data:
        raise HTTPException(status_code=404, detail="Booking not found")

    booking = booking_res.data[0]

    if booking["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not allowed")

    # Update status
    supabase.table("bookings") \
        .update({"status": "cancelled"}) \
        .eq("id", booking_id) \
        .execute()

    # Send emails
    email_body = cancel_email_template(booking, booking["profiles"])

    send_email(booking["contact_email"], "Booking Cancelled", email_body)

    if booking["profiles"]["email"] != booking["contact_email"]:
        send_email(booking["profiles"]["email"], "Booking Cancelled", email_body)

    return {
        "status": "success",
        "message": "Booking cancelled successfully"
    }


# -------------------------
# Calculate Refund API
# ------------------------- 
def calculate_refund(booking):
    visit = datetime.fromisoformat(booking["visit_date"])
    now = datetime.utcnow()

    hours_left = (visit - now).total_seconds() / 3600

    rules = supabase.table("cancellation_policy") \
        .select("*") \
        .order("hours_before", desc=True) \
        .execute().data

    for rule in rules:
        if hours_left >= rule["hours_before"]:
            fee = booking["total_amount"] * (rule["fee_percent"] / 100)
            return fee, booking["total_amount"] - fee

    return 0, booking["total_amount"]

# -------------------------
# Revenue API
# ------------------------- 
@app.get("/admin/revenue", tags=["Admin"])
def get_revenue():

    cash_received = supabase.table("bookings") \
        .select("total_amount") \
        .eq("payment_received", True) \
        .execute().data

    total_revenue = sum(b["total_amount"] or 0 for b in cash_received)

    return {
        "cash_received_revenue": total_revenue,
        "bookings_count": len(cash_received)
    }

# -------------------------
# Cash Revenue API
# ------------------------- 
@app.get("/admin/cash-revenue", tags=["Admin"])
def cash_revenue():

    now = datetime.utcnow()

    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=today_start.weekday())
    month_start = today_start.replace(day=1)
    year_start = today_start.replace(month=1, day=1)

    def sum_cash(from_date):
        rows = supabase_admin.table("bookings") \
            .select("total_amount") \
            .eq("payment_received", True) \
            .gte("created_at", from_date.isoformat()) \
            .execute().data

        return sum(r["total_amount"] or 0 for r in rows)

    return {
        "today": sum_cash(today_start),
        "this_week": sum_cash(week_start),
        "this_month": sum_cash(month_start),
        "this_year": sum_cash(year_start)
    }

# -------------------------
# Download Receipt API
# ------------------------- 
@app.get("/booking/{booking_id}/receipt", tags=["User"])
def download_receipt(booking_id: str):

    booking = supabase.table("bookings") \
        .select(
            """
            id,
            visit_date,
            adults,
            children,
            total_amount,
            payment_method,
            payment_received,
            contact_name,
            booking_types(name),
            time_slots(slot_name,start_time,end_time)
            """
        ) \
        .eq("id", booking_id) \
        .execute().data[0]

    os.makedirs("receipts", exist_ok=True)
    filename = f"receipts/receipt_{booking_id}.pdf"

    c = canvas.Canvas(filename, pagesize=A4)

    # Header
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 800, "Animal Farm - Booking Receipt")

    c.setFont("Helvetica", 10)
    c.drawString(50, 780, f"Booking ID: {booking['id']}")

    # Body
    y = 740
    c.setFont("Helvetica", 11)

    c.drawString(50, y, f"Name: {booking['contact_name']}")
    y -= 20
    c.drawString(50, y, f"Visit Date: {booking['visit_date']}")
    y -= 20
    c.drawString(50, y, f"Booking Type: {booking['booking_types']['name']}")
    y -= 20
    # c.drawString(50, y, f"Time Slot: {booking['time_slots']['start_time']} - {booking['time_slots']['end_time']}")
    c.drawString( 50, y, f"Time Slot: {booking['time_slots']['slot_name']} "f"({booking['time_slots']['start_time']} - {booking['time_slots']['end_time']})")
    y -= 20
    c.drawString(50, y, f"Adults: {booking['adults']}")
    y -= 20
    c.drawString(50, y, f"Children: {booking['children']}")

    # Divider
    y -= 30
    c.line(50, y, 550, y)
    y -= 30

    # Amount Section
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, f"Total Amount: ₹{booking['total_amount']}")

    y -= 25
    c.setFont("Helvetica", 11)
    c.drawString(
        50,
        y,
        f"Payment Method: Cash"
    )

    y -= 20
    payment_status = "PAID" if booking["payment_received"] else "PAY AT COUNTER"
    c.drawString(50, y, f"Payment Status: {payment_status}")

    # Footer
    y -= 40
    c.setFont("Helvetica", 10)
    c.drawString(50, y, "Thank you for booking with Animal Farm!")
    y -= 15
    c.drawString(50, y, "We look forward to welcoming you")

    c.save()

    return FileResponse(filename, filename=f"receipt_{booking_id}.pdf")

# -------------------------
# Payment Received email Receipt API
# ------------------------- 
def payment_received_email_template(booking):
    return f"""
    <h2>Payment Received ✅</h2>
    <p>Dear {booking['contact_name']},</p>

    <p>We have successfully received your cash payment.</p>

    <p><b>Booking ID:</b> {booking['id']}</p>
    <p><b>Visit Date:</b> {booking['visit_date']}</p>
    <p><b>Total Amount Paid:</b> ₹{booking['total_amount']}</p>

    <br/>
    <p>Thank you for visiting <b>Animal Farm</b></p>
    <p>We look forward to welcoming you!</p>
    """

