from dataclasses import dataclass

from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


@dataclass
class Task(Base):
    __tablename__ = 'tasks'

    id: int = Column(Integer, primary_key=True)
    title: str = Column(String)
    description: str = Column(String)
    completed: bool = Column(Boolean)

    def __repr__(self):
        return f'<Task {self.title}>'
