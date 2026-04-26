from sqlalchemy import Column, String, Integer, JSON, Boolean, ForeignKey, BigInteger, DateTime, Index
from sqlalchemy.sql import func
from app.db.session import Base
from sqlalchemy.orm import relationship


class Folder(Base):
    __tablename__ = "folders"
    id = Column(String, primary_key=True)
    name = Column(String)
    section = Column(String)
    device_group_id = Column(String)
    parent_id = Column(String, nullable=True)
    sort_order = Column(Integer, default=0)
    rules = relationship("CachedRule", back_populates="folder", cascade="all, delete-orphan")

class CachedRule(Base):
    __tablename__ = "cached_rules"
    id = Column(String, primary_key=True)
    ext_id = Column(String, unique=True)
    name = Column(String)
    folder_id = Column(String, ForeignKey("folders.id"))
    folder_sort_order = Column(Integer, default=0)
    data = Column(JSON)
    is_modified = Column(Boolean, default=False)
    modified_at = Column(String, nullable=True)
    folder = relationship("Folder", back_populates="rules")

class CachedObject(Base):
    __tablename__ = "cached_objects"
    ext_id = Column(String, primary_key=True)
    name = Column(String)
    type = Column(String)
    category = Column(String)
    device_group_id = Column(String)
    data = Column(JSON)

class DeviceMeta(Base):
    __tablename__ = "device_meta"
    device_id = Column(String, primary_key=True)
    name = Column(String)


class NatFolder(Base):
    __tablename__ = "nat_folders"
    id = Column(String, primary_key=True)
    name = Column(String)
    device_group_id = Column(String)
    section = Column(String, default='pre')
    sort_order = Column(Integer, default=0)
    rules = relationship("CachedNatRule", back_populates="folder", cascade="all, delete-orphan")


class CachedNatRule(Base):
    __tablename__ = "cached_nat_rules"
    id = Column(String, primary_key=True)
    ext_id = Column(String, unique=True)
    name = Column(String)
    folder_id = Column(String, ForeignKey("nat_folders.id"), nullable=True)
    folder_sort_order = Column(Integer, default=0)
    device_group_id = Column(String)
    data = Column(JSON)
    is_modified = Column(Boolean, default=False)
    modified_at = Column(String, nullable=True)
    folder = relationship("NatFolder", back_populates="rules")


class CachedLog(Base):
    """Local cache of logs fetched from NGFW. Auto-purged after 1 hour."""
    __tablename__ = "cached_logs"

    id              = Column(BigInteger, primary_key=True, autoincrement=True)
    device_group_id = Column(String(128), nullable=False)
    log_type        = Column(String(32),  nullable=False)   # traffic/ips/av/audit
    event_time      = Column(DateTime(timezone=True), nullable=True)
    src_ip          = Column(String(64),  nullable=True)
    dst_ip          = Column(String(64),  nullable=True)
    dst_port        = Column(Integer,     nullable=True)
    action          = Column(String(64),  nullable=True)
    data            = Column(JSON,        nullable=False)
    fetched_at      = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index('ix_clog_device_type',  'device_group_id', 'log_type'),
        Index('ix_clog_event_time',   'device_group_id', 'log_type', 'event_time'),
        Index('ix_clog_fetched_at',   'fetched_at'),
        Index('ix_clog_src_ip',       'src_ip'),
        Index('ix_clog_dst_ip',       'dst_ip'),
        Index('ix_clog_action',       'action'),
    )
