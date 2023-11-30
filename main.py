from motor.motor_asyncio import AsyncIOMotorClient
from fastapi import FastAPI, HTTPException
from models import UserCreate
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()
db_client = AsyncIOMotorClient("mongodb://localhost:27017")
db = db_client.db_arg_test
users_collection = db.users
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Set up CORS middleware
origins = [
    "http://localhost:3000",  # Allow your Next.js frontend
    "http://127.0.0.1:3000",  # Also allow if accessed via 127.0.0.1
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "javainuse-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
@app.post("/register")
async def register(user: UserCreate):
    # Suppose your user collection is named 'users'
    users_collection = db.users

    existing_user = await users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = pwd_context.hash(user.password)
    await users_collection.insert_one({"email": user.email, "hashed_password": hashed_password})
    return {"message": "User registered successfully"}

@app.post("/login")
async def login(user: UserCreate):
    db_user = await users_collection.find_one({"email": user.email})
    if not db_user or not pwd_context.verify(user.password, db_user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    # Generate JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
