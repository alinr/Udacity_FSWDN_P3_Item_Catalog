from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Item, User, Base
from datetime import datetime

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="John Doe", email="john-doe@udacity.com",
             picture='http://lorempixel.com/output/people-q-c-400-400-9.jpg')
session.add(User1)
session.commit()


# Create some categories
session.add(Category(name="Soccer", description=""))
session.add(Category(name="Basketball", description=""))
session.add(Category(name="Baseball", description=""))
session.add(Category(name="Frisbee", description=""))
session.add(Category(name="Snowboarding", description=""))
session.add(Category(name="Rock Climbing", description=""))
session.add(Category(name="Football", description=""))
session.add(Category(name="Skating", description=""))
session.add(Category(name="Hockey", description=""))

session.commit()


# Create some Items
session.add(Item(name="Soccer Ball", description="Black & White", picture="", picture_data="", created_on=datetime.utcnow(), user_id="1", category_id="1"))
session.add(Item(name="Soccer Shoes", description="Yellow & Pink", picture="", picture_data="", created_on=datetime.utcnow(), user_id="1", category_id="1"))

session.commit()

print "Added Categories"
