import os
from typing import Annotated

import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Response, Depends
from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pwdlib import PasswordHash
from sqlmodel import Session, create_engine, select

from dto.login import LoginRequest, SignupRequest
from dto.user import User

load_dotenv()
app = FastAPI()

SECRET_KEY = os.getenv("SECRET_KEY")
COOKIE_NAME = "access_token"
IS_PROD = os.getenv("env").lower() == "prod"

password_hash = PasswordHash.recommended()

sqlite_file_name = os.getenv("database_file")
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)


# https://fastapi.tiangolo.com/tutorial/sql-databases/#create-an-engine
def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "message": "Invalid input data",
            "errors": exc.errors(),
        },
    )


def create_access_token(user_id, role):
    payload = {"user_id": user_id, "role": role}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def setup_access_token(response: Response, user: User):
    token = create_access_token(user.id, user.role)

    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=IS_PROD,
    )


@app.post("/signup")
def signup(
        response: Response,
        data: SignupRequest,
        session: SessionDep,
):
    statement = select(User).where(User.username == data.username)
    user = session.exec(statement).first()
    if user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="username already in use",
        )

    user = User(username=data.username, password=password_hash.hash(data.password))

    session.add(user)
    session.commit()
    session.refresh(user)

    setup_access_token(response, user)

    return {}


@app.post("/login")
def login(
        response: Response,
        data: LoginRequest,
        session: SessionDep,
):
    statement = select(User).where(User.username == data.username)
    user = session.exec(statement).first()
    if not user or not password_hash.verify(data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    setup_access_token(response, user)

    return {}
