# import jwt
# from fastapi import FastAPI, Depends, HTTPException, status
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from passlib.hash import bcrypt
# from pydantic import BaseModel
# from motor.motor_asyncio import AsyncIOMotorClient
# from bson import ObjectId

# app = FastAPI()

# JWT_SECRET = 'myjwtsecret'
# MONGO_DETAILS = "mongodb://localhost:27017"

# client = AsyncIOMotorClient(MONGO_DETAILS)
# database = client.my_database
# user_collection = database.get_collection("users")

# class UserInDB(BaseModel):
#     id: str
#     username: str
#     password_hash: str

#     class Config:
#         orm_mode = True
#         json_encoders = {ObjectId: str}

# class UserCreate(BaseModel):
#     username: str
#     password: str

# oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

# async def get_user(username: str):
#     user = await user_collection.find_one({"username": username})
#     if user:
#         return UserInDB(**user)

# async def authenticate_user(username: str, password: str):
#     user = await get_user(username)
#     if not user:
#         return False
#     if not bcrypt.verify(password, user.password_hash):
#         return False
#     return user

# @app.post('/token')
# async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
#     user = await authenticate_user(form_data.username, form_data.password)
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail='Invalid username or password'
#         )

#     user_dict = user.dict()
#     user_dict.pop("password_hash")
#     token = jwt.encode(user_dict, JWT_SECRET)

#     return {'access_token': token, 'token_type': 'bearer'}

# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     try:
#         payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
#         user = await user_collection.find_one({"_id": ObjectId(payload["id"])})
#         if user:
#             return UserInDB(**user)
#     except:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail='Invalid username or password'
#         )

# @app.post('/users', response_model=UserInDB)
# async def create_user(user: UserCreate):
#     user_obj = UserInDB(
#         id=str(ObjectId()),
#         username=user.username,
#         password_hash=bcrypt.hash(user.password)
#     )
#     await user_collection.insert_one(user_obj.dict())
#     return user_obj

# @app.get('/users/me', response_model=UserInDB)
# async def get_user(user: UserInDB = Depends(get_current_user)):
#     return user

import jwt
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.hash import bcrypt
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId

app = FastAPI()

JWT_SECRET = 'myjwtsecret'
MONGO_DETAILS = "mongodb://localhost:27017"

client = AsyncIOMotorClient(MONGO_DETAILS)
database = client.my_database
user_collection = database.get_collection("users")

class UserInDB(BaseModel):
    id: str
    username: str
    password_hash: str

    class Config:
        from_attributes = True
        json_encoders = {ObjectId: str}

class UserCreate(BaseModel):
    username: str
    password: str

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

async def get_user(username: str) -> UserInDB:
    user_dict = await user_collection.find_one({"username": username})
    if user_dict:
        return UserInDB(**user_dict)
    return None

async def authenticate_user(username: str, password: str) -> UserInDB:
    user = await get_user(username)
    if not user:
        return None
    if not bcrypt.verify(password, user.password_hash):
        return None
    return user

@app.post('/token')
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid username or password'
        )

    user_dict = user.dict()
    user_dict.pop("password_hash")
    token = jwt.encode(user_dict, JWT_SECRET)

    return {'access_token': token, 'token_type': 'bearer'}

async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user = await user_collection.find_one({"_id": ObjectId(payload["id"])})
        if user:
            return UserInDB(**user)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid username or password'
        )

@app.post('/users', response_model=UserInDB)
async def create_user(user: UserCreate) -> UserInDB:
    user_obj = UserInDB(
        id=str(ObjectId()),
        username=user.username,
        password_hash=bcrypt.hash(user.password)
    )
    await user_collection.insert_one(user_obj.dict())
    return user_obj

@app.get('/users/me', response_model=UserInDB)
async def get_user(user: UserInDB = Depends(get_current_user)) -> UserInDB:
    return user
