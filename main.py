import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
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

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Frontend URL
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
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
    login: str   # email OR phone


class DirectResetRequest(BaseModel):
    user_id: str
    new_password: str

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
def reset_password_direct(data: DirectResetRequest):

    try:
        supabase.auth.admin.update_user_by_id(
            data.user_id,
            {"password": data.new_password}
        )

        return {
            "status": "success",
            "message": "Password updated successfully"
        }

    except:
        raise HTTPException(status_code=400, detail="Reset failed")
