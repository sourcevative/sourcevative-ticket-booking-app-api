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
import re
from supabase import create_client
from dotenv import load_dotenv
from fastapi import Body
from datetime import datetime, timedelta
from datetime import datetime, date
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from fastapi.responses import FileResponse
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import uuid
from fastapi import Header


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

class ResetPasswordRequest(BaseModel):
    access_token: str
    new_password: str


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
        res = supabase.table("profiles").select("id, email").eq("email", data.login).execute()
    else:
        res = supabase.table("profiles").select("id, email").eq("phone", data.login).execute()

    if not res.data:
        # Don't reveal if account exists (security)
        return {"status": "ok", "message": "If account exists, reset link has been sent"}

    user = res.data[0]

    # 2. Generate secure token
    token = secrets.token_urlsafe(32)

    expires_at = (datetime.utcnow() + timedelta(minutes=30)).isoformat()

    # 3. Store token
    supabase.table("password_reset_tokens").insert({
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

    if len(data.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    # 1. Find token
    token_row = supabase.table("password_reset_tokens") \
        .select("*") \
        .eq("token", data.token) \
        .execute()

    if not token_row.data:
        raise HTTPException(status_code=400, detail="Invalid or expired reset link")

    token_data = token_row.data[0]

    # 2. Check expiry
    if datetime.fromisoformat(token_data["expires_at"]) < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Reset link expired")

    user_id = token_data["user_id"]

    # 3. Update password
    supabase.auth.admin.update_user_by_id(user_id, {
        "password": data.new_password
    })

    # 4. Delete token (one-time use)
    supabase.table("password_reset_tokens") \
        .delete() \
        .eq("token", data.token) \
        .execute()

    return {"status": "success", "message": "Password updated successfully"}

# -------------------------
# Create Booking Type API
# -------------------------
class BookingTypeRequest(BaseModel):
    name: str
    adult_price: float
    child_price: float
    admin_id: str

@app.post("/admin/booking-type", tags=["Admin"])
def create_booking_type(data: BookingTypeRequest):
    # Use admin client to bypass RLS policies
    return supabase_admin.table("booking_types").insert({
        "name": data.name,
        "adult_price": data.adult_price,
        "child_price": data.child_price,
        "created_by": data.admin_id
    }).execute()

@app.get("/admin/booking-types", tags=["Admin"])
def get_admin_booking_types():
    # Use admin client to bypass RLS policies
    return supabase_admin.table("booking_types") \
        .select("id, name, adult_price, child_price, profiles(name,email)") \
        .execute()


class TimeSlotRequest(BaseModel):
    booking_type_id: str
    start_time: str
    end_time: str
    capacity: int

@app.post("/admin/time-slot", tags=["Admin"])
def create_time_slot(data: TimeSlotRequest):
    # Use admin client to bypass RLS policies
    return supabase_admin.table("time_slots").insert({
        "booking_type_id": data.booking_type_id,
        "start_time": data.start_time,
        "end_time": data.end_time,
        "capacity": data.capacity
    }).execute()

@app.get("/booking-types", tags=["User"])
def get_booking_types():
    return supabase.table("booking_types") \
        .select("*") \
        .eq("is_active", True) \
        .execute()

@app.get("/time-slots/{booking_type_id}", tags=["User"])
def get_time_slots(booking_type_id: str):
    return supabase.table("time_slots") \
        .select("*") \
        .eq("booking_type_id", booking_type_id) \
        .eq("is_active", True) \
        .execute()

# -------------------------
# Admin Update Booking Type API
# -------------------------
class UpdateBookingTypeRequest(BaseModel):
    name: str
    adult_price: float
    child_price: float
    is_active: bool

@app.put("/admin/booking-type/{booking_type_id}", tags=["Admin"])
def update_booking_type(booking_type_id: str, data: UpdateBookingTypeRequest):
    # Use admin client to bypass RLS policies
    return supabase_admin.table("booking_types") \
        .update({
            "name": data.name,
            "adult_price": data.adult_price,
            "child_price": data.child_price,
            "is_active": data.is_active
        }) \
        .eq("id", booking_type_id) \
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
    addons: list[str]   # list of addon IDs

# -------------------------
# Admin Addons API
# -------------------------
@app.post("/admin/addon", tags=["Admin"])
def create_addon(name: str, description: str, price: float):
    # Use admin client to bypass RLS policies
    return supabase_admin.table("addons").insert({
        "name": name,
        "description": description,
        "price": price
    }).execute()

@app.get("/addons", tags=["User"])
def get_addons():
    return supabase.table("addons").select("*").eq("is_active", True).execute()

class PriceRequest(BaseModel):
    booking_type_id: str
    adults: int
    children: int
    addons: list[str]
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
@app.post("/calculate-price", tags=["User"])
def calculate_price(data: PriceRequest):

    # Get booking type prices (check both active and inactive for price calculation)
    booking_type_result = supabase.table("booking_types") \
        .select("id, adult_price, child_price, is_active, name") \
        .eq("id", data.booking_type_id) \
        .execute()
    
    # Validate that booking type exists
    if not booking_type_result.data:
        raise HTTPException(
            status_code=404,
            detail=f"Booking type with ID {data.booking_type_id} not found. Please verify the booking type ID is correct."
        )
    
    bt = booking_type_result.data[0]
    
    # Warn if booking type is inactive (but still allow price calculation)
    if not bt.get("is_active", True):
        # You can uncomment this to prevent price calculation for inactive types
        # raise HTTPException(
        #     status_code=400,
        #     detail=f"Booking type '{bt.get('name', 'Unknown')}' is currently inactive"
        # )
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
@app.post("/book", tags=["User"])
def create_booking(data: BookingRequest):

    # capacity check code stays here
    # Convert date to ISO format string for database operations
    visit_date_str = data.visit_date.isoformat() if isinstance(data.visit_date, date) else str(data.visit_date)

    booking = supabase.table("bookings").insert({
        "user_id": data.user_id,
        "booking_type_id": data.booking_type_id,
        "time_slot_id": data.time_slot_id,
        "visit_date": visit_date_str,  # Convert date to string for JSON serialization
        "adults": data.adults,
        "children": data.children,
        "contact_name": data.contact_name,
        "contact_email": data.contact_email,
        "contact_phone": data.contact_phone,
        "preferred_contact": data.preferred_contact,
        "notes": data.notes
    }).execute()

    booking_id = booking.data[0]["id"]

    for addon_id in data.addons:
        supabase.table("booking_addons").insert({
            "booking_id": booking_id,
            "addon_id": addon_id
        }).execute()

    return booking

    booking_id = booking.data[0]["id"]

    for addon_id in data.addons:
        supabase.table("booking_addons").insert({
            "booking_id": booking_id,
            "addon_id": addon_id
        }).execute()

    # 🔹 Get login user's email
    user = supabase.table("profiles") \
        .select("email") \
        .eq("id", data.user_id) \
        .execute().data[0]

    # 🔹 Prepare email
    email_body = booking_email_template(data, booking.data[0])

    # 🔹 Send to contact email
    send_email(data.contact_email, "Your Booking Confirmation", email_body)

    # 🔹 Send to login email if different
    if user["email"] != data.contact_email:
        send_email(user["email"], "Your Booking Confirmation", email_body)

    return booking

# -------------------------
# User Cancel Booking API
# -------------------------
@app.post("/cancel-booking/{booking_id}", tags=["User"])
def user_cancel_booking(booking_id: str, user_id: str):

    # check booking belongs to user
    booking = supabase.table("bookings") \
        .select("user_id") \
        .eq("id", booking_id) \
        .execute()

    if booking.data[0]["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not allowed")

    return supabase.table("bookings") \
        .update({"status": "cancelled"}) \
        .eq("id", booking_id) \
        .execute()

# -------------------------
# Admin Show User Bookings API
# -------------------------
@app.get("/admin/user-bookings/{user_id}", tags=["Admin"])
def get_user_bookings(user_id: str):

    return supabase.table("bookings") \
        .select(
            "id, visit_date, status, adults, children, booking_types(name), time_slots(start_time,end_time), booking_addons(addons(name,price))"
        ) \
        .eq("user_id", user_id) \
        .execute()

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
            "id, visit_date, status, adults, children, booking_types(name), time_slots(start_time,end_time), booking_addons(addons(name,price))"
        ) \
        .eq("user_id", user_id) \
        .order("created_at", desc=True) \
        .execute()

# -------------------------
# Send Email Confirmation API
# -------------------------
def send_email(to_email, subject, body):
    msg = MIMEText(body, "html")
    msg["Subject"] = subject
    msg["From"] = os.getenv("EMAIL_USER")
    msg["To"] = to_email

    server = smtplib.SMTP(os.getenv("EMAIL_HOST"), int(os.getenv("EMAIL_PORT")))
    server.starttls()
    server.login(os.getenv("EMAIL_USER"), os.getenv("EMAIL_PASS"))
    server.send_message(msg)
    server.quit()

def booking_email_template(data, booking):
    return f"""
    <h2>Booking Confirmed 🎉</h2>
    <p><b>Name:</b> {data.contact_name}</p>
    <p><b>Visit Date:</b> {data.visit_date}</p>
    <p><b>Adults:</b> {data.adults} | <b>Children:</b> {data.children}</p>
    <p><b>Booking ID:</b> {booking['id']}</p>
    <p>Thank you for booking with Animal Farm!</p>
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

    booking = supabase.table("bookings") \
        .select("*, profiles(email)") \
        .eq("id", booking_id) \
        .execute().data[0]

    if booking["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not allowed")

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

    confirmed = supabase.table("bookings") \
        .select("total_amount") \
        .eq("status", "confirmed") \
        .execute().data

    cancelled = supabase.table("bookings") \
        .select("cancellation_fee") \
        .eq("status", "cancelled") \
        .execute().data

    confirmed_total = sum(b["total_amount"] or 0 for b in confirmed)
    cancelled_total = sum(b["cancellation_fee"] or 0 for b in cancelled)

    return {
        "booking_revenue": confirmed_total,
        "cancellation_revenue": cancelled_total,
        "total_revenue": confirmed_total + cancelled_total
    }

# -------------------------
# Revenue Stats API
# ------------------------- 
@app.get("/admin/revenue-stats", tags=["Admin"])
def revenue_stats():

    return {
        "today": supabase.rpc("revenue_today").execute().data,
        "this_week": supabase.rpc("revenue_week").execute().data,
        "this_month": supabase.rpc("revenue_month").execute().data,
        "this_year": supabase.rpc("revenue_year").execute().data
    }

# -------------------------
# Download Receipt API
# ------------------------- 
@app.get("/booking/{booking_id}/receipt", tags=["User"])
def download_receipt(booking_id: str):

    booking = supabase.table("bookings") \
        .select(
            "id, visit_date, adults, children, total_amount, status, contact_name, booking_types(name), time_slots(start_time,end_time)"
        ) \
        .eq("id", booking_id) \
        .execute().data[0]

    # ✅ Windows-safe folder
    os.makedirs("receipts", exist_ok=True)

    filename = f"receipts/receipt_{booking_id}.pdf"
    c = canvas.Canvas(filename, pagesize=A4)

    c.drawString(50, 800, "Animal Farm Booking Receipt")
    c.drawString(50, 770, f"Booking ID: {booking['id']}")
    c.drawString(50, 750, f"Name: {booking['contact_name']}")
    c.drawString(50, 730, f"Visit Date: {booking['visit_date']}")
    c.drawString(50, 710, f"Booking Type: {booking['booking_types']['name']}")
    c.drawString(50, 690, f"Time Slot: {booking['time_slots']['start_time']} - {booking['time_slots']['end_time']}")
    c.drawString(50, 670, f"Adults: {booking['adults']}")
    c.drawString(50, 650, f"Children: {booking['children']}")
    c.drawString(50, 630, f"Total Paid: ₹{booking['total_amount']}")

    c.drawString(50, 580, "Thank you for booking with Animal Farm!")
    c.save()

    return FileResponse(filename, filename=f"receipt_{booking_id}.pdf")
