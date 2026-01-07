import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from supabase import create_client
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

app = FastAPI(
    title="Animal Farm API",
    description="Authentication system for Farm Booking",
    version="1.0"
)


# -------------------------
# Request Body
# -------------------------
class SignupRequest(BaseModel):
    name: str
    email: str
    phone: str
    password: str

class LoginRequest(BaseModel):
    login: str   # email OR phone
    password: str

class ForgotPasswordRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    access_token: str
    new_password: str


# -------------------------
# Signup API
# -------------------------
@app.post("/signup", tags=["Authentication"])
def signup(data: SignupRequest):
    try:
        # We Create user in Supabase Auth
        auth_response = supabase.auth.admin.create_user({
            "email": data.email,
            "password": data.password,
            "email_confirm": True
        })

        user = auth_response.user

        # Store extra info in profiles table
        profile = {
            "id": user.id,
            "name": data.name,
            "phone": data.phone,
            "email": data.email
        }

        supabase.table("profiles").insert(profile).execute()

        return {
            "status": "success",
            "message": "User created successfully",
            "user_id": user.id
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


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

        # Login using Supabase Auth
        auth = supabase.auth.sign_in_with_password({
            "email": email,
            "password": data.password
        })

        user = auth.user
        session = auth.session

        # Get user profile
        profile = supabase.table("profiles").select("*").eq("id", user.id).execute()

        return {
            "status": "success",
            "access_token": session.access_token,
            "user": profile.data[0]
        }

    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid login credentials")

# -------------------------
# Forgot Password API
# -------------------------
@app.post("/forgot-password", tags=["Authentication"])
def forgot_password(data: ForgotPasswordRequest):
    try:
        supabase.auth.reset_password_for_email(
            data.email,
            {"redirect_to": "http://localhost:3000/reset-password"}
        )

        return {
            "status": "success",
            "message": "Reset password link sent to your email"
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# -------------------------
# Reset Password API
# -------------------------
@app.post("/reset-password", tags=["Authentication"])
def reset_password(data: ResetPasswordRequest):
    try:
        supabase.auth.set_session(data.access_token, "")

        supabase.auth.update_user({
            "password": data.new_password
        })

        return {
            "status": "success",
            "message": "Password updated successfully"
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid or expired reset link")
