from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from app.db import Base
from app.timeutil import utc_now


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    target = Column(String, nullable=False)
    scope_notes = Column(Text, nullable=False)
    scope = Column(JSON, nullable=False, default=dict)
    authorized = Column(Boolean, nullable=False, default=False)
    authorized_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now)

    scans = relationship("Scan", back_populates="project")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    status = Column(String, nullable=False, default="pending")
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")
    audit_entries = relationship("AuditEntry", back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    module = Column(String, nullable=False)
    type = Column(String, nullable=False)
    value = Column(String, nullable=False)
    data = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=utc_now)

    scan = relationship("Scan", back_populates="findings")


class AuditEntry(Base):
    __tablename__ = "audit_entries"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    module = Column(String, nullable=False)
    target = Column(String, nullable=False)
    url = Column(String, nullable=True)
    outcome = Column(String, nullable=False)
    requested_at = Column(DateTime, default=utc_now)

    scan = relationship("Scan", back_populates="audit_entries")
