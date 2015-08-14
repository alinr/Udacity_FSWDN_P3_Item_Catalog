#!/usr/bin/env python
#
# database_setup.py -- database structure for an item catalog

from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, Text, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True, autoincrement=True) # Google Oauth-Id to big for String
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id



class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(250), nullable=False)
    description = Column(String(250), nullable=True)



    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description
        }

    def serializeToXml(self, content):
        content.append("<Category>")
        content.append("<ID>%s</ID>" % self.id)
        content.append("<Name>%s</Name>" % self.name)
        content.append("<Description>%s</Description>" % self.description)
        content.append("</Category>")





class Item(Base):
    __tablename__ = 'item'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    picture = Column(Text, nullable=True)
    picture_data = Column(LargeBinary, nullable=True)
    created_on = Column(String(255), nullable=True)

    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    category_id = Column(Integer, ForeignKey("category.id"))
    category = relationship(Category)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'created_on': self.created_on
        }

    def serializeToXml(self, content):
        content.append("<Item>")
        content.append("<ID>%s</ID>" % self.id)
        content.append("<Name>%s</Name>" % self.name.replace('&', '&amp;'))

        if self.description:
            content.append("<Description>%s</Description>" % self.description.replace('&', '&amp;'))
        else:
            content.append("<Description/>")
        content.append("<CreatedOn>%s</CreatedOn>" % self.created_on)
        content.append("</Item>")


engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)
