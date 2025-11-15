import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File as UploadFileType, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from pymongo import ReturnDocument
from bson import ObjectId

from database import db
from schemas import (
    User, Folder, File as FileModel, Share,
    SignUpRequest, LoginRequest, TokenResponse,
    FolderCreate, FolderRename, ShareRequest
)

# Environment and constants
SECRET_KEY = os.getenv("JWT_SECRET", "dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

# Password hashing
# Use pbkdf2_sha256 to avoid external bcrypt backend issues
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

app = FastAPI(title="Drive-like API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helpers

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user_by_email(email: str):
    return db["user"].find_one({"email": email.lower()})


def decode_token(token: str):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    user_id: str = payload.get("sub")
    if not user_id:
        raise HTTPException(401, "Invalid token")
    user = db["user"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(401, "User not found")
    return user


def get_current_user(request: Request, token: Optional[str] = None):
    # Prefer Authorization header; fallback to token query parameter
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    parsed_token = None
    if auth and auth.lower().startswith("bearer "):
        parsed_token = auth.split(" ", 1)[1].strip()
    elif token:
        parsed_token = token
    if not parsed_token:
        raise HTTPException(401, "Not authenticated")
    try:
        return decode_token(parsed_token)
    except JWTError:
        raise HTTPException(401, "Invalid token")


# Auth routes
@app.post("/auth/signup", response_model=TokenResponse)
def signup(payload: SignUpRequest):
    if get_user_by_email(payload.email):
        raise HTTPException(400, "Email already registered")
    user_doc = {
        "email": payload.email.lower(),
        "name": payload.name,
        "password_hash": get_password_hash(payload.password),
        "role": "user",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result = db["user"].insert_one(user_doc)
    token = create_access_token({"sub": str(result.inserted_id)})
    return TokenResponse(access_token=token)


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    user = get_user_by_email(payload.email)
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(401, "Invalid credentials")
    token = create_access_token({"sub": str(user["_id"])})
    return TokenResponse(access_token=token)


# Folder routes
@app.post("/folders", response_model=dict)
def create_folder(payload: FolderCreate, user=Depends(get_current_user)):
    folder = {
        "name": payload.name,
        "owner_id": str(user["_id"]),
        "parent_id": payload.parent_id,
        "path": [],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["folder"].insert_one(folder)
    folder["_id"] = str(res.inserted_id)
    return {"folder": folder}


@app.get("/folders", response_model=dict)
def list_folders(parent_id: Optional[str] = None, user=Depends(get_current_user)):
    q = {"owner_id": str(user["_id"])}
    if parent_id is None:
        q["parent_id"] = None
    else:
        q["parent_id"] = parent_id
    items = list(db["folder"].find(q))
    for f in items:
        f["_id"] = str(f["_id"])
    return {"folders": items}


@app.patch("/folders/{folder_id}", response_model=dict)
def rename_folder(folder_id: str, payload: FolderRename, user=Depends(get_current_user)):
    folder = db["folder"].find_one_and_update(
        {"_id": ObjectId(folder_id), "owner_id": str(user["_id"])},
        {"$set": {"name": payload.name, "updated_at": datetime.now(timezone.utc)}},
        return_document=ReturnDocument.AFTER,
    )
    if not folder:
        raise HTTPException(404, "Folder not found")
    folder["_id"] = str(folder["_id"])
    return {"folder": folder}


@app.delete("/folders/{folder_id}")
def delete_folder(folder_id: str, user=Depends(get_current_user)):
    folder = db["folder"].find_one({"_id": ObjectId(folder_id), "owner_id": str(user["_id"])})
    if not folder:
        raise HTTPException(404, "Folder not found")
    # delete files in folder metadata (not blobs)
    db["file"].delete_many({"folder_id": folder_id, "owner_id": str(user["_id"])})
    db["folder"].delete_one({"_id": ObjectId(folder_id)})
    return {"status": "ok"}


# Storage setup: local filesystem under /data
STORAGE_ROOT = os.getenv("STORAGE_ROOT", "/data")
os.makedirs(STORAGE_ROOT, exist_ok=True)


# File routes
@app.post("/files/upload", response_model=dict)
async def upload_file(
    file: UploadFile = UploadFileType(...),
    folder_id: Optional[str] = Form(None),
    user=Depends(get_current_user),
):
    contents = await file.read()
    # Create user directory
    user_dir = os.path.join(STORAGE_ROOT, str(user["_id"]))
    os.makedirs(user_dir, exist_ok=True)

    # storage key includes folder if present (flattened here)
    storage_key = os.path.join(user_dir, file.filename)
    with open(storage_key, "wb") as f:
        f.write(contents)

    doc = {
        "name": file.filename,
        "owner_id": str(user["_id"]),
        "folder_id": folder_id,
        "size": len(contents),
        "mime_type": file.content_type or "application/octet-stream",
        "storage_key": storage_key,
        "version": 1,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["file"].insert_one(doc)
    doc["_id"] = str(res.inserted_id)
    return {"file": doc}


@app.get("/files", response_model=dict)
def list_files(folder_id: Optional[str] = None, q: Optional[str] = None, ftype: Optional[str] = None, user=Depends(get_current_user)):
    query = {"owner_id": str(user["_id"]) }
    if folder_id is None:
        query["folder_id"] = None
    else:
        query["folder_id"] = folder_id
    if q:
        query["name"] = {"$regex": q, "$options": "i"}
    if ftype:
        query["mime_type"] = {"$regex": ftype}
    items = list(db["file"].find(query).sort("updated_at", -1))
    for it in items:
        it["_id"] = str(it["_id"])
    return {"files": items}


from fastapi.responses import FileResponse

@app.get("/files/{file_id}/download")
def download_file(file_id: str, request: Request, token: Optional[str] = None):
    user = get_current_user(request, token)
    doc = db["file"].find_one({"_id": ObjectId(file_id)})
    if not doc:
        raise HTTPException(404, "Not found")
    # permission: owner only for now
    if doc["owner_id"] != str(user["_id"]):
        raise HTTPException(403, "Forbidden")
    return FileResponse(doc["storage_key"], filename=doc["name"]) 


# Sharing (basic)
@app.post("/share", response_model=dict)
def create_share(payload: ShareRequest, user=Depends(get_current_user)):
    # ensure resource exists and owned by user
    coll = "file" if payload.resource_type == "file" else "folder"
    res = db[coll].find_one({"_id": ObjectId(payload.resource_id)})
    if not res:
        raise HTTPException(404, "Resource not found")
    if res["owner_id"] != str(user["_id"]):
        raise HTTPException(403, "Forbidden")

    share = {
        "resource_type": payload.resource_type,
        "resource_id": payload.resource_id,
        "granted_by": str(user["_id"]),
        "granted_to": payload.granted_to,  # could be user id or email
        "permission": payload.permission,
        "created_at": datetime.now(timezone.utc)
    }
    db["share"].insert_one(share)
    return {"share": share}


@app.get("/me", response_model=dict)
def me(user=Depends(get_current_user)):
    user["_id"] = str(user["_id"])
    user.pop("password_hash", None)
    return {"user": user}


# Root and health
@app.get("/")
def root():
    return {"status": "ok", "service": "drive-backend"}
