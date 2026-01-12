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

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

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
            "user": profile.data[0]
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid login credentials")

# -------------------------
# Forgot Password API
# -------------------------
@app.post("/forgot-password", tags=["Authentication"])
def forgot_password(data: ForgotPasswordRequest):

    if "@" in data.login:
        res = supabase.table("profiles").select("id").eq("email", data.login).execute()
    else:
        res = supabase.table("profiles").select("id").eq("phone", data.login).execute()

    if len(res.data) == 0:
        raise HTTPException(
            status_code=404,
            detail="Account not found. Please signup first."
        )

    return {
        "status": "verified",
        "user_id": res.data[0]["id"]
    }

# -------------------------
# Reset Password API
# -------------------------

@app.post("/reset-password-direct", tags=["Authentication"])
async def reset_password_direct(request: Request):
    """
    Reset password directly using user_id.
    This endpoint matches the frontend reset password page that accepts user_id from URL params.
    Accepts both snake_case (user_id, new_password) and camelCase (userId, newPassword) field names.
    """
    try:
        # Parse request body manually to handle both naming conventions
        body = await request.json()
        
        # Normalize field names: accept both snake_case and camelCase
        user_id = body.get("user_id") or body.get("userId")
        new_password = body.get("new_password") or body.get("newPassword")
        
        # Validate required fields
        if not user_id:
            raise HTTPException(
                status_code=400,
                detail="Missing required field: 'user_id' or 'userId'"
            )
        if not new_password:
            raise HTTPException(
                status_code=400,
                detail="Missing required field: 'new_password' or 'newPassword'"
            )
        
        # Normalize user_id (strip whitespace)
        user_id = str(user_id).strip()
        new_password = str(new_password)
        
    except HTTPException:
        raise
    except Exception as parse_error:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid request body: {str(parse_error)}"
        )
    
    try:
        # Check if user_id is provided (matches frontend validation)
        if not user_id or user_id == "":
            raise HTTPException(
                status_code=400, 
                detail="Invalid reset link. Please request a new password reset."
            )

        # Validate user_id is a valid UUID format
        try:
            uuid.UUID(user_id)
        except (ValueError, AttributeError):
            raise HTTPException(
                status_code=400, 
                detail="Invalid reset link. Please request a new password reset."
            )

        # Validate password is provided and meets minimum length requirement
        if not new_password or len(new_password) < 6:
            raise HTTPException(
                status_code=400, 
                detail="Password must be at least 6 characters long."
            )

        # Verify user exists in profiles table
        profile_result = supabase.table("profiles").select("id, email").eq("id", user_id).execute()
        
        if len(profile_result.data) == 0:
            raise HTTPException(
                status_code=404, 
                detail="Invalid reset link. Please request a new password reset."
            )

        # Update password using admin API
        try:
            result = supabase.auth.admin.update_user_by_id(
                user_id,
                {"password": new_password}
            )

            return {
                "status": "success",
                "message": "Your password has been updated successfully."
            }
        
        except Exception as supabase_error:
            error_message = str(supabase_error)
            error_lower = error_message.lower()
            
            # Handle specific Supabase errors with user-friendly messages
            if "user_not_found" in error_lower or "user not found" in error_lower:
                raise HTTPException(
                    status_code=404, 
                    detail="Invalid reset link. Please request a new password reset."
                )
            elif "weak_password" in error_lower:
                raise HTTPException(
                    status_code=400, 
                    detail="Password is too weak. Please choose a stronger password."
                )
            elif "same_password" in error_lower:
                raise HTTPException(
                    status_code=400, 
                    detail="New password must be different from the current password."
                )
            elif "not_admin" in error_lower or "no_authorization" in error_lower or "unauthorized" in error_lower:
                raise HTTPException(
                    status_code=500, 
                    detail="We could not reset your password. Please try again."
                )
            elif "invalid" in error_lower and "uuid" in error_lower:
                raise HTTPException(
                    status_code=400, 
                    detail="Invalid reset link. Please request a new password reset."
                )
            else:
                # Generic error message for unknown errors
                raise HTTPException(
                    status_code=400, 
                    detail="We could not reset your password. Please try again."
                )

    except HTTPException:
        raise
    except Exception as e:
        # Catch any unexpected errors and return user-friendly message
        raise HTTPException(
            status_code=400, 
            detail="We could not reset your password. Please try again."
        )
