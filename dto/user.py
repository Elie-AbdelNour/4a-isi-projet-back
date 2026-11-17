from enum import StrEnum

from sqlmodel import SQLModel, Field


class UserRole(StrEnum):
    ADMIN = "admin"
    USER = "user"


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str
    password: str
    role: UserRole = Field(default=UserRole.USER)
    is_blocked: bool = Field(default=False)
