import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

# BookSeries
# id | name
class BookSeries(Base):
    __tablename__ = 'bookseries'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'id': self.id,
        }

# Individual Books
#id|name|author|language|year|genre|description|review|bookseries_id|bookseries
class IndividualBook(Base):
    __tablename__ = 'individualbook'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    author = Column(String(80), nullable=False)
    language = Column(String(80), nullable=False)
    year = Column(Integer)
    genre = Column(String(80), nullable=False)
    description = Column(String(250))
    review = Column(String(500))
    bookseries_id = Column(Integer, ForeignKey('bookseries.id'))
    bookseries = relationship(BookSeries)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'name': self.name,
            'author': self.author,
            'language': self.language,
            'year': self.year,
            'genre': self.genre,
            'description': self.description,
            'review':self.review,
        }

engine = create_engine('sqlite:///bookseries_User.db')

Base.metadata.create_all(engine)
