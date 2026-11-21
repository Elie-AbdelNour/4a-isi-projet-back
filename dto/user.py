from enum import StrEnum

from sqlalchemy import Enum
from sqlmodel import SQLModel, Field


class UserRole(StrEnum):
    ADMIN = "admin"
    USER = "user"


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str
    password_hash: str
    role: UserRole = Field(
        default=UserRole.USER,
        # by default, SQL alchemy will use enum.name instead of enum.value, causing it to use USER as a value
        # while our database accepts "user", the same goes for admin.
        # values_callable makes us able to specify what it should use:
        # https://docs.sqlalchemy.org/en/20/core/type_basics.html#sqlalchemy.types.Enum.params.values_callable
        sa_type=Enum(UserRole, values_callable=lambda roles: [r.value for r in roles]),
    )
    is_blocked: bool = Field(default=False)
