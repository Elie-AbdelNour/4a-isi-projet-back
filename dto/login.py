from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class SignupRequest(BaseModel):
    username: str
    password: str = Field(min_length=8, max_length=20)
