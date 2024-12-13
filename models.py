from sqlalchemy import Boolean, String, Column, Integer, Date, ForeignKey
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    id= Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True)
    floor = Column(Integer)
    section = Column(String(50))
    password = Column(String(100))
    worker = Column(Boolean)
    admin = Column(Boolean)


class Report(Base):
    __tablename__ = "reports"

    id= Column(Integer, primary_key=True, index=True)
    userid = Column(Integer, index=True)
    place = Column(String(50))
    kind = Column(String(50))
    name = Column(String(70))
    report_title = Column(String(70))
    date = Column(String(70))
    desc = Column(String(255))
    notes = Column(String(255))
    done_by = Column(Integer)
    done_by2 = Column(Integer)
    done = Column(Boolean)

    
class Process(Base):
    __tablename__ = "processes"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(70))
    desc = Column(String(120))
    date = Column(String(70))
    status = Column(Boolean)
    report_id = Column(Integer)



class Section(Base):
    __tablename__ = "sections"

    id= Column(Integer, primary_key=True, index=True)
    name = Column(String(50))
    floor = Column(Integer)

