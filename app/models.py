from pydantic import BaseModel
from sqlalchemy import BigInteger, Boolean, Column, Integer, Text, String, DateTime
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class FileScanRequest(BaseModel):
    file_id: int


class StoredFile(Base):
    __tablename__ = "stored_file"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    salted_hash = Column(Text, nullable=False)
    size = Column(Integer, nullable=False)
    type = Column(Text, nullable=False)
    save_path = Column(Text, nullable=False)


class ScanTable(Base):
    __tablename__ = "scan_table"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    detect = Column(Boolean, nullable=True)
    file_id = Column(BigInteger, unique=True, nullable=True)
    step2_detail = Column(Text, nullable=True)
    step2detail = Column(Text, nullable=True)


class FileStatus(Base):
    __tablename__ = "file_status"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    file_id = Column(BigInteger, unique=True, nullable=True)
    gscan_status = Column(Boolean, nullable=True, default=-1)
    dlp_status = Column(Boolean, nullable=True, default=-1)
    vt_status = Column(Boolean, nullable=True, default=-1)


class FileUpload(Base):
    __tablename__ = "file_upload"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    org_saas_id = Column(Integer, nullable=False)
    saas_file_id = Column(String(255), nullable=True)
    upload_ts = Column(DateTime, nullable=True)
    salted_hash = Column(String(255), nullable=True)
    deleted = Column(Boolean, default=False, nullable=False)