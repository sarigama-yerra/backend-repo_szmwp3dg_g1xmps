from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import datetime

# Users
class User(BaseModel):
    email: EmailStr
    name: str
    password_hash: str
    avatar_url: Optional[str] = None
    role: Literal["user", "admin"] = "user"
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

# Folders
class Folder(BaseModel):
    name: str
    owner_id: str
    parent_id: Optional[str] = None
    path: List[str] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

# Files
class File(BaseModel):
    name: str
    owner_id: str
    folder_id: Optional[str] = None
    size: int = 0
    mime_type: str
    storage_key: str  # path in storage (local or S3)
    checksum: Optional[str] = None
    version: int = 1
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

# Sharing
class Share(BaseModel):
    resource_type: Literal["file", "folder"]
    resource_id: str
    granted_by: str
    granted_to: str  # user id or email for invites
    permission: Literal["view", "edit"] = "view"
    created_at: Optional[datetime] = None

# Auth
class SignUpRequest(BaseModel):
    email: EmailStr
    name: str
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class FolderCreate(BaseModel):
    name: str
    parent_id: Optional[str] = None

class FolderRename(BaseModel):
    name: str

class ShareRequest(BaseModel):
    resource_type: Literal["file", "folder"]
    resource_id: str
    granted_to: str
    permission: Literal["view", "edit"] = "view"
