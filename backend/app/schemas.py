from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator


class ProjectCreate(BaseModel):
    name: str
    target: str
    scope_notes: str
    authorized: bool

    @field_validator("authorized")
    @classmethod
    def must_be_authorized(cls, v: bool) -> bool:
        if not v:
            raise ValueError("authorized must be true to create a project")
        return v

    @field_validator("scope_notes")
    @classmethod
    def scope_notes_must_not_be_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("scope_notes must not be blank")
        return v


class ProjectOut(BaseModel):
    id: int
    name: str
    target: str
    scope_notes: str
    authorized: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanOut(BaseModel):
    id: int
    project_id: int
    status: str
    started_at: datetime | None
    finished_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class FindingOut(BaseModel):
    id: int
    module: str
    type: str
    value: str
    data: dict

    model_config = ConfigDict(from_attributes=True)
