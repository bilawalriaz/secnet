import uuid
from sqlalchemy import Column, String, Boolean, ForeignKey, DateTime, Integer, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database.session import Base


class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String)
    role = Column(String, default="user")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    endpoints = relationship("Endpoint", back_populates="user")
    endpoint_groups = relationship("EndpointGroup", back_populates="user")
    scans = relationship("Scan", back_populates="user")
    scheduled_scans = relationship("ScheduledScan", back_populates="user")
    api_keys = relationship("ApiKey", back_populates="user")


class EndpointGroup(Base):
    __tablename__ = "endpoint_groups"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    name = Column(String, nullable=False)
    description = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    user = relationship("User", back_populates="endpoint_groups")
    endpoints = relationship("Endpoint", back_populates="group")


class Endpoint(Base):
    __tablename__ = "endpoints"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    name = Column(String, nullable=False)
    address = Column(String, nullable=False)
    type = Column(String, default="ip")  # ip, hostname, etc.
    description = Column(String)
    group_id = Column(UUID(as_uuid=True), ForeignKey("endpoint_groups.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    is_active = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User", back_populates="endpoints")
    group = relationship("EndpointGroup", back_populates="endpoints")
    scan_targets = relationship("ScanTarget", back_populates="endpoint")
    scan_results = relationship("ScanResult", back_populates="endpoint")


class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    name = Column(String, nullable=False)
    type = Column(String, nullable=False)  # port-scan, os-detection, etc.
    parameters = Column(JSON, nullable=True)
    scheduled_at = Column(DateTime(timezone=True), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String, default="pending")  # pending, running, completed, failed
    
    # Relationships
    user = relationship("User", back_populates="scans")
    targets = relationship("ScanTarget", back_populates="scan", cascade="all, delete-orphan")
    results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")


class ScanTarget(Base):
    __tablename__ = "scan_targets"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"))
    endpoint_id = Column(UUID(as_uuid=True), ForeignKey("endpoints.id"))
    
    # Relationships
    scan = relationship("Scan", back_populates="targets")
    endpoint = relationship("Endpoint", back_populates="scan_targets")


class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"))
    endpoint_id = Column(UUID(as_uuid=True), ForeignKey("endpoints.id"))
    raw_results = Column(JSON)
    open_ports = Column(Integer, default=0)
    vulnerabilities = Column(Integer, default=0)
    os_detection = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    scan = relationship("Scan", back_populates="results")
    endpoint = relationship("Endpoint", back_populates="scan_results")


class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    name = Column(String, nullable=False)
    scan_config = Column(JSON, nullable=False)
    schedule_type = Column(String, nullable=False)  # daily, weekly, monthly, custom
    cron_expression = Column(String, nullable=True)
    next_run = Column(DateTime(timezone=True), nullable=True)
    last_run = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User", back_populates="scheduled_scans")


class ApiKey(Base):
    __tablename__ = "api_keys"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    name = Column(String, nullable=False)
    key_hash = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
