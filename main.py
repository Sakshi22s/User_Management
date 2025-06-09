from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, EmailStr, validator, Field
from typing import Optional, List
import asyncpg
import bcrypt
import jwt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import os
import re
import asyncio
from contextlib import asynccontextmanager
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database connection pool
db_pool = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global db_pool
    db_pool = await asyncpg.create_pool(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", 5432),
        user=os.getenv("DB_USER", ""),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", ""),
        min_size=10,
        max_size=20,
    )
    yield
    # Shutdown
    await db_pool.close()

app = FastAPI(
    title="User Management APIs",
    description="APIs for user management",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this properly for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()
JWT_SECRET = os.getenv("JWT_SECRET", "workwithme22s")
JWT_ALGORITHM = "HS256"

# ============================================
# PYDANTIC MODELS
# ============================================

class UserInviteRequest(BaseModel):
    email: EmailStr
    role_id: int
    designation_id: int
    first_name: Optional[str] = None
    last_name: Optional[str] = None

# class UserRegistrationRequest(BaseModel):
#     token: str
#     username: str
#     password: str
#     first_name: Optional[str] = None
#     last_name: Optional[str] = None

class UserRegistrationRequest(BaseModel):
    token: str
    username: str
    # email_id: EmailStr
    email: EmailStr = Field(..., alias="email_id")
    password: str
    role_id: int
    designation_id: int
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    profile_image_url: Optional[str] = None
    phone_number: Optional[int] = None
    is_active: bool = True
    is_email_verified: bool = False
    is_password_set: bool = False
    
    @validator('username')
    def validate_username(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]{3,30}$', v):
            raise ValueError('Username must be 3-30 characters long and contain only letters, numbers, and underscores')
        return v
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        return v

# class LoginRequest(BaseModel):
#     username: str
#     password: str
class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class UpdateUserRequest(BaseModel):
    role_id: Optional[int] = None
    designation_id: Optional[int] = None

class UserResponse(BaseModel):
    user_id: str
    username: str
    email_id: str
    first_name: Optional[str]
    last_name: Optional[str]
    role_name: str
    designation_name: str
    department: Optional[str]
    is_active: bool
    is_email_verified: bool
    is_password_set: bool
    last_login: Optional[datetime]
    created_at: datetime

# ============================================
# UTILITY FUNCTIONS
# ============================================

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=24)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

async def get_db_connection():
    """Get database connection from pool"""
    return await db_pool.acquire()

async def release_db_connection(conn):
    """Release database connection back to pool"""
    await db_pool.release(conn)

async def send_email(to_email: str, subject: str, html_body: str):
    print("Sending mail to" , to_email)
    print("Password" , os.getenv("SMTP_PASSWORD"))
    """Send email using SMTP"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = os.getenv("SMTP_FROM", "sakshimoreyeahs@gmail.com")
        print("Sending mail from " ,  msg['From'])
        msg['To'] = to_email
        
        html_part = MIMEText(html_body, 'html')
        msg.attach(html_part)
        
        # with smtplib.SMTP(os.getenv("SMTP_HOST", "localhost"), int(os.getenv("SMTP_PORT", 587))) as server:
        #     server.starttls()
        #     server.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD"))
        #     server.send_message(msg)
        smtp_password = "avautnrtcccuenyk"
        smtp_user = "sakshimoreyeahs@gmail.com"
        with smtplib.SMTP(os.getenv("SMTP_HOST", "smtp.gmail.com"), int(os.getenv("SMTP_PORT", 587)), timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            # server.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD"))
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
            
        logger.info(f"Email sent successfully to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to send email")

# ============================================
# AUTHENTICATION & AUTHORIZATION
# ============================================

# async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
#     """Get current authenticated user"""
#     try:
#         payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
#         print(payload,"##########")
#         user_id: str = payload.get("sub")
#         if user_id is None:
#             raise HTTPException(status_code=401, detail="Invalid authentication credentials")
#     except jwt.PyJWTError:
#         raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
#     conn = await get_db_connection()
#     try:
#         user = await conn.fetchrow(
#             "SELECT user_id, username, email_id, role_id FROM user_details WHERE user_id = $1 AND is_active = true",
#             user_id
#         )
#         if user is None:
#             raise HTTPException(status_code=401, detail="User not found or inactive")
#         return user
#     finally:
#         await release_db_connection(conn)
#updated to User name
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current authenticated user"""
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        print(payload, "##########")

        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

    conn = await get_db_connection()
    try:
        user = await conn.fetchrow(
            "SELECT user_id, username, email_id, role_id FROM user_details WHERE username = $1 AND is_active = true",
            username
        )
        if user is None:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        return user
    finally:
        await release_db_connection(conn)


def require_role(required_roles: List[str]):
    """Dependency factory to require specific roles"""
    def role_checker(current_user = Depends(get_current_user)):
        # print(current_user," current_user ##########")
        if current_user['role_name'] not in required_roles:
            raise HTTPException(
                status_code=403, 
                detail="You do not have permission to perform this action."
            )
        return current_user
    return role_checker

# ============================================
# API ENDPOINTS
# ============================================

# @app.post("/api/auth/login")
# async def login(login_data: LoginRequest):
#     """User login endpoint"""
#     conn = await get_db_connection()
#     try:
#         user = await conn.fetchrow(
#             "SELECT username, password_hash, role_id FROM user_details WHERE username = $1 AND is_active = true",
#             login_data.username
#         )
#         print("USer Details", user)
        
#         if not user or not verify_password(login_data.password, user['password_hash']):
#             raise HTTPException(status_code=401, detail="Invalid username or password")
        
#         # Update last login
#         await conn.execute(
#             "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = $1",
#             user['user_id']
#         )
        
#         # Create access token
#         access_token = create_access_token(data={"sub": str(user['user_id'])})
        
#         return {
#             "access_token": access_token,
#             "token_type": "bearer",
#             "user": {
#                 "user_id": str(user['user_id']),
#                 "username": user['username'],
#                 "role": user['role_name']
#             }
#         }
#     finally:
#         await release_db_connection(conn)

@app.post("/api/auth/login")
async def login(login_data: LoginRequest):
    """User login using email and password"""
    conn = await get_db_connection()
    try:
        user = await conn.fetchrow(
            """
            SELECT u.user_id, u.email_id, u.password_hash, r.role_name
            FROM user_details u
            JOIN role_name r ON u.role_id = r.role_id
            WHERE u.email_id = $1 AND u.is_active = true
            """,
            login_data.email
        )

        if not user or not verify_password(login_data.password, user['password_hash']):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        # Update last login
        await conn.execute(
            "UPDATE user_details SET last_login = CURRENT_TIMESTAMP WHERE user_id = $1",
            user['user_id']
        )

        # Create access token
        access_token = create_access_token(data={"sub": str(user['user_id'])})
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "user_id": str(user['user_id']),
                "email": user['email_id'],
                "role": user['role_name']
            }
        }
    finally:
        await release_db_connection(conn)

class LoginUpdate(BaseModel):
    user_id : str
    username : str
    email_id : str 
    password_hash : str
    role_id : int
    designation_id : int
    profile_image_url : str
    phone_number : str
    is_active : bool

@app.put("/updatelogin")
async def update_login(user_details: LoginUpdate):
    updated_at = datetime.utcnow()

    conn = await get_db_connection()
    try:
        result = await conn.execute("""
            UPDATE user_details 
            SET 
                username = $1,
                email_id = $2,
                password_hash = $3,
                role_id = $4,
                designation_id = $5,
                profile_image_url = $6,
                phone_number = $7,
                is_active = $8,
                updated_at = $9
            WHERE user_id = $10
        """,
        user_details.username,
        user_details.email_id,
        user_details.password_hash,
        user_details.role_id,
        user_details.designation_id,
        user_details.profile_image_url,
        user_details.phone_number,
        user_details.is_active,
        updated_at,
        user_details.user_id
        )

        if result == "UPDATE 0":
            raise HTTPException(status_code=404, detail="User not found")

        return {"message": f"User with id {user_details.user_id} updated successfully"}

    finally:
        await conn.close()



class UserInput(BaseModel):
    user : str

@app.post("/deleteuser")
async def delete_user(
    input: UserInput,
    current_user = Depends(require_role(["superadmin", "admin"])) 
):
    user_to_delete = input.user
    print(f"Delete your User: {user_to_delete}")
    print(f"Request made by SuperAdmin: {current_user['username']}")

    conn = await get_db_connection()
    try:
        result = await conn.execute(
            "DELETE FROM user_details WHERE username=$1", user_to_delete
        )
        return {"message": f"{user_to_delete} deleted", "db_response": result}
    finally:
        await conn.close()

from uuid import uuid4
import secrets
from datetime import datetime, timedelta

@app.post("/api/users/invite")
async def invite_user(
    invite_data: UserInviteRequest,
    background_tasks: BackgroundTasks,
    current_user = Depends(require_role(["superadmin"]))
):
    """Send user invitation (SuperAdmin only)"""
    conn = await get_db_connection()
    try:
        # Generate unique token and expiration
        invitation_token = secrets.token_urlsafe(32)
        invitation_id = str(uuid4())
        expires_at = datetime.utcnow() + timedelta(days=7)

        # Insert invitation into DB
        await conn.execute(
            """
            INSERT INTO invitations (
                id, email, invited_by_user_id, role_id, designation_id,
                first_name, last_name, invitation_token, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """,
            invitation_id,
            invite_data.email,
            current_user['user_id'],
            invite_data.role_id,
            invite_data.designation_id,
            invite_data.first_name,
            invite_data.last_name,
            invitation_token,
            expires_at
        )

        # Create invitation link
        invitation_link = f"{os.getenv('FRONTEND_URL', 'http://localhost:3000')}/register?token={invitation_token}"

        # Email content
        html_body = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2>Welcome to Our Platform!</h2>
            <p>Hi {invite_data.first_name or ''},</p>
            <p>You've been invited to join our platform by {current_user['username']}. Click the link below to set up your account:</p>
            <div style="margin: 30px 0;">
                <a href="{invitation_link}" 
                   style="background-color: #4CAF50; color: white; padding: 12px 24px; 
                          text-decoration: none; border-radius: 4px; display: inline-block;">
                    Set Up Your Account
                </a>
            </div>
            <p>This invitation will expire in 7 days.</p>
            <p>If you didn't expect this invitation, you can safely ignore this email.</p>
            <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
            <p style="color: #666; font-size: 12px;">
                If the button doesn't work, copy and paste this link: {invitation_link}
            </p>
        </div>
        """

        # Send email in background
        background_tasks.add_task(
            send_email,
            invite_data.email,
            "You're invited to join our platform",
            html_body
        )

        return {
            "success": True,
            "message": "Invitation sent successfully",
            "invitation_id": invitation_id
        }

    finally:
        await release_db_connection(conn)


# @app.get("/api/users/validate-invitation/{token}")
# async def validate_invitation(token: str):
#     """Validate invitation token"""
#     conn = await get_db_connection()
#     try:
#         result = await conn.fetchrow(
#             "SELECT * FROM invitations Where invitations =$1",
#             token
#         )
#         print("Validate Invitation user results ", result)
#         if not result['is_valid']:
#             raise HTTPException(status_code=400, detail=result['message'])
#         # print("Validate Invitation user detail", result['user_data'])
#         return {
#             "success": True,
#             "data": result['user_data']
#         }
        
#     finally:
#         await release_db_connection(conn)


@app.get("/api/users/validate-invitation/{token}")
async def validate_invitation(token: str):
    """Validate invitation token"""
    conn = await get_db_connection()
    try:
        result = await conn.fetchrow(
            "SELECT * FROM invitations WHERE invitation_token = $1",
            token
        )
        print("Validate Invitation user results:", result)

        if not result:
            raise HTTPException(status_code=404, detail="Invitation not found.")

        if result["accepted_at"] is not None:
            raise HTTPException(status_code=400, detail="Invitation already accepted.")

        if result["expires_at"] and result["expires_at"] < datetime.utcnow():
            raise HTTPException(status_code=400, detail="Invitation token has expired.")
        
        

        # Optional: You can return specific user data instead of raw result['user_data']
        user_data = {
            "email": result["email"],
            "first_name": result["first_name"],
            "last_name": result["last_name"],
            "role_id": result["role_id"],
            "designation_id": result["designation_id"],
            "invitation_token":result["invitation_token"],
            "accepted_at": datetime.utcnow()
        }

        return {
            "success": True,
            "data": user_data
        }

    finally:
        await release_db_connection(conn)


@app.post("/api/users/register")
async def register_user(registration_data: UserRegistrationRequest):
    print("Registration Data", registration_data)
    """Complete user registration"""
    conn = await get_db_connection()
    try:
        # Hash password
        password_hash = hash_password(registration_data.password)
        print(registration_data.username,
            password_hash,
            registration_data.first_name,
            registration_data.last_name,
            registration_data.token)
        
        # Call stored procedure to complete registration
        result = await conn.fetchrow(
            """
            INSERT INTO user_details (email_id,username, password_hash,role_id,designation_id, first_name, last_name, invitation_token)
            VALUES ($1, $2, $3, $4, $5,$6,$7,$8)
            RETURNING *;
            """,
            registration_data.email,
            registration_data.username,
            password_hash,
            registration_data.role_id,
            registration_data.designation_id,
            registration_data.first_name,
            registration_data.last_name,
            registration_data.token
        )
        return {
            "success": True,
            "message": "Registration completed successfully",
            "user_id": str(result['user_id'])
        }
        
    finally:
        await release_db_connection(conn)



# @app.post("/api/users/register")
# async def register_user(registration_data: UserRegistrationRequest):
#     print("Registration Data", registration_data)
#     conn = await get_db_connection()
#     try:
#         # Hash password
#         password_hash = hash_password(registration_data.password)

#         # Validate invitation
#         invitation = await conn.fetchrow(
#             "SELECT * FROM invitations WHERE invitation_token = $1",
#             registration_data.token
#         )

#         if not invitation:
#             raise HTTPException(status_code=404, detail="Invalid invitation token.")
#         if invitation["accepted_at"]:
#             raise HTTPException(status_code=400, detail="Invitation already used.")
#         if invitation["expires_at"] and invitation["expires_at"] < datetime.utcnow():
#             raise HTTPException(status_code=400, detail="Invitation expired.")

#         # Insert user
#         result = await conn.fetchrow(
#             """
#             INSERT INTO user_details (invitation_token, username, password, firstname, lastname)
#             VALUES ($1, $2, $3, $4, $5)
#             RETURNING id
#             """,
#             registration_data.token,
#             registration_data.username,
#             password_hash,
#             registration_data.first_name,
#             registration_data.last_name
#         )

#         # Mark invitation as accepted
#         await conn.execute(
#             "UPDATE invitations SET accepted_at = $1 WHERE invitation_token = $2",
#             datetime.utcnow(),
#             registration_data.token
#         )

#         return {
#             "success": True,
#             "message": "Registration completed successfully",
#             "user_id": str(result["id"])
#         }

#     finally:
#         await release_db_connection(conn)





@app.get("/api/users/management")
async def get_users_management(
    page: int = 1,
    limit: int = 50,
    current_user = Depends(require_role(["superadmin"]))
):
    """Get users for management (SuperAdmin only)"""
    conn = await get_db_connection()
    try:
        result = await conn.fetchrow(
            "SELECT * FROM get_users_for_management($1, $2, $3)",
            current_user['user_id'],
            page,
            limit
        )
        
        return {
            "total_count": result['total_count'],
            "users": result['users_data'],
            "page": page,
            "limit": limit
        }
        
    finally:
        await release_db_connection(conn)

@app.put("/api/users/{user_id}")
async def update_user(
    user_id: str,
    update_data: UpdateUserRequest,
    current_user = Depends(require_role(["superadmin"]))
):
    """Update user role/designation (SuperAdmin only)"""
    conn = await get_db_connection()
    try:
        result = await conn.fetchrow(
            "SELECT * FROM update_user_role_designation($1, $2, $3, $4)",
            current_user['user_id'],
            user_id,
            update_data.role_id,
            update_data.designation_id
        )
        
        if not result['success']:
            raise HTTPException(status_code=400, detail=result['message'])
        
        return {
            "success": True,
            "message": result['message']
        }
        
    finally:
        await release_db_connection(conn)

@app.delete("/api/users/{user_id}")
async def deactivate_user(
    user_id: str,
    current_user = Depends(require_role(["superadmin"]))
):
    """Deactivate user (SuperAdmin only)"""
    conn = await get_db_connection()
    try:
        result = await conn.fetchrow(
            "SELECT * FROM deactivate_user($1, $2)",
            current_user['user_id'],
            user_id
        )
        
        if not result['success']:
            raise HTTPException(status_code=400, detail=result['message'])
        
        return {
            "success": True,
            "message": result['message']
        }
        
    finally:
        await release_db_connection(conn)

@app.get("/api/invitations/pending")
async def get_pending_invitations(
    current_user = Depends(require_role(["superadmin", "admin"]))
):
    """Get pending invitations"""
    conn = await get_db_connection()
    try:
        result = await conn.fetchrow(
            "SELECT * FROM get_pending_invitations($1)",
            current_user['user_id']
        )
        
        return {
            "invitations": result['invitations_data']
        }
        
    finally:
        await release_db_connection(conn)

@app.delete("/api/invitations/{invitation_id}")
async def cancel_invitation(
    invitation_id: int,
    current_user = Depends(require_role(["superadmin"]))
):
    """Cancel invitation (SuperAdmin only)"""
    conn = await get_db_connection()
    try:
        result = await conn.fetchrow(
            "SELECT * FROM cancel_invitation($1, $2)",
            current_user['user_id'],
            invitation_id
        )
        
        if not result['success']:
            raise HTTPException(status_code=400, detail=result['message'])
        
        return {
            "success": True,
            "message": result['message']
        }
        
    finally:    
        await release_db_connection(conn)

@app.get("/api/roles")
async def get_roles(current_user = Depends(get_current_user)):
    print(current_user)
    """Get active roles for dropdowns"""
    conn = await get_db_connection()
    try:
        roles = await conn.fetch("SELECT * FROM role_name")
        return [dict(role) for role in roles]
    finally:
        await release_db_connection(conn)


class RoleInput(BaseModel):
    role: str

# Endpoint
@app.post("/deleteRole")
async def delete_role(input: RoleInput):
    role_to_delete = input.role  # Store in local variable
    print(f"Role to delete: {role_to_delete}")

    conn = await get_db_connection()
    try:
        result = await conn.execute(
            "DELETE FROM role_name WHERE role_name = $1", role_to_delete
        )
        return {"message": f"{role_to_delete} deleted", "db_response": result}
    finally:
        await conn.close()

class RoleCreate(BaseModel):
    role_name: str
    role_description: str
    is_active: bool
    permissions: str  # or List[str] if you're storing as JSON/array

@app.post("/createRole")
async def create_role(role: RoleCreate):
    created_at = updated_at = datetime.utcnow()
    
    conn = await get_db_connection()
    try:
        await conn.execute("""
            INSERT INTO role_name (role_name, role_description, is_active, created_at, updated_at, permissions)
            VALUES ($1, $2, $3, $4, $5, $6)
        """, role.role_name, role.role_description, role.is_active, created_at, updated_at, role.permissions)
        
        return {"message": f"Role '{role.role_name}' inserted successfully"}
    finally:
        await conn.close()

class RoleUpdate(BaseModel):
    role_id: int
    role_name: str
    role_description: str
    is_active: bool
    permissions: str  # adjust type if needed

@app.put("/updateRole")
async def update_role(role: RoleUpdate):
    updated_at = datetime.utcnow()
    
    conn = await get_db_connection()
    try:
        result = await conn.execute("""
            UPDATE role_name
            SET role_name = $1,
                role_description = $2,
                is_active = $3,
                updated_at = $4,
                permissions = $5
            WHERE role_id = $6
        """, role.role_name, role.role_description, role.is_active, updated_at, role.permissions, role.role_id)
        
        if result == "UPDATE 0":
            raise HTTPException(status_code=404, detail="Role not found")
        
        return {"message": f"Role with id {role.role_id} updated successfully"}
    finally:
        await conn.close()


#Designation-----

@app.get("/api/designations")
async def get_designations(current_user = Depends(get_current_user)):
    """Get active designations for dropdowns"""
    conn = await get_db_connection()
    try:
        designations = await conn.fetch("SELECT * FROM designations")
        return [dict(designation) for designation in designations]
    finally:
        await release_db_connection(conn)

class DesignationCreate(BaseModel):
    designation_id : int
    designation_name : str
    designation_description : str
    department : str
    is_active : bool
    level_hierarchy : int 

@app.post("/createDesignation")
async def create_designation(designation: DesignationCreate):
    created_at = updated_at = datetime.utcnow()

    conn = await get_db_connection()
    try:
        await conn.execute("""
        INSERT into designations(designation_id,designation_name, designation_description, department, level_hierarchy, is_active, created_at, updated_at)
        VAlUES($1,$2,$3,$4,$5,$6,$7,$8)
    """,designation.designation_id, designation.designation_name, designation.designation_description, designation.department, designation.level_hierarchy, designation.is_active, created_at, updated_at)
        
        return {"message" : f"Role'{designation.designation_name}' inserted successfully"}
    finally:
        await conn.close()



class DesignationUpdate(BaseModel):
    designation_id : int
    designation_name : str
    designation_description : str
    department : str
    is_active : bool
    level_hierarchy : int

@app.put("/updateDesignation")
async def update_designation(designations : DesignationUpdate):
    updated_at = datetime.utcnow()

    conn = await get_db_connection()
    try:
        result = await conn.execute("""
            UPDATE designations
            SET designation_name = $1,
                designation_description=$2,
                department = $3,
                is_active = $4,
                level_hierarchy = $5,
                updated_at = $6
            Where designation_id = $7
            """, designations.designation_name, designations.designation_description, designations.department, designations.is_active, designations.level_hierarchy, updated_at, designations.designation_id)

        if result == "UPDATE 0":
            raise HTTPException(status_code=404, detail="Description not found")
        
        return {"message" : f"Designation with id{designations.designation_id} Updated Successfully"}

    finally:
        await conn.close()



class DesignationInput(BaseModel):
    designation : str


@app.post("/deleteDesignation")
async def delete_designation(input : DesignationInput):
    desig_to_delete = input.designation
    print(f"Delete Designation : {desig_to_delete}")

    conn = await get_db_connection()
    try:
        result = await conn.execute(
            "DELETE FROM designations WHERE designation_name = $1", desig_to_delete
        )

        return {"message" : f"{desig_to_delete} deleted", "db_response" : result}
    finally:
        await conn.close()




@app.get("/api/users/profile")
async def get_user_profile(current_user = Depends(get_current_user)):
    """Get current user profile"""
    conn = await get_db_connection()
    try:
        profile = await conn.fetchrow(
            "SELECT * FROM user_details WHERE user_id = $1",
            current_user['user_id']
        )
        return dict(profile)
    finally:
        await release_db_connection(conn)

# ============================================
# BACKGROUND TASKS
# ============================================

@app.on_event("startup")
async def startup_event():
    """Run startup tasks"""
    # Schedule cleanup of expired invitations
    asyncio.create_task(cleanup_expired_invitations_task())

async def cleanup_expired_invitations_task():
    """Background task to cleanup expired invitations"""
    while True:
        try:
            conn = await get_db_connection()
            try:
                result = await conn.fetchval("SELECT cleanup_expired_invitations()")
                if result > 0:
                    logger.info(f"Cleaned up {result} expired invitations")
            finally:
                await release_db_connection(conn)
        except Exception as e:
            logger.error(f"Error in cleanup task: {str(e)}")
        
        # Run every hour
        await asyncio.sleep(3600)

# ============================================
# HEALTH CHECK
# ============================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        conn = await get_db_connection()
        await conn.fetchval("SELECT 1")
        await release_db_connection(conn)
        return {"status": "healthy", "timestamp": datetime.utcnow()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database connection failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app,  port=8000)