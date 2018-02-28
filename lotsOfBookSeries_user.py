# -*- coding: cp1252 -*-
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, BookSeries, IndividualBook, User

engine = create_engine('sqlite:///bookseries_User.db')
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
# # Create dummy user
# User1 = User(name="Robo Barista", email="tinnyTim@udacity.com",
#              picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
User1 = User(name="Radhika Godugu", email="radhik.g@gmail.com")
session.add(User1)
session.commit()

# 1.HarryPotter,
# 2.PeterRabbit,
# 3.TheChroniclesofNarnia,
# 4.James Bond,
# 5.Diary of a Wimpy Kid,
# 6.The Lord Of The Rings

bookseries1 = BookSeries(user_id=1, name="Harry Potter")
session.add(bookseries1)
session.commit()
#id| name| author| language| year| genre| description| bookseries_id|bookseries
IndividualBook1 = IndividualBook(user_id=1, name="The Philosopher's Stone",
                         author="J. K. Rowling",
                         language="English", year=1997,
                         genre="Fantasy",
                         description="Harry Potter's FIRST year at Hogwarts",
                         review="This book series has been part of my childhood, I can so relate to these charecters!!!",
                         bookseries=bookseries1)
session.add(IndividualBook1)
session.commit()

IndividualBook2 = IndividualBook(user_id=1, name="The Chamber of Secrets",
                         author="J. K. Rowling",
                         language="English", year=1998,
                         genre="Fantasy",
                         description="Harry Potter's SECOND year at Hogwarts",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries1)
session.add(IndividualBook2)
session.commit()

IndividualBook3 = IndividualBook(user_id=1, name="The Prisoner of Azkaban ",
                         author="J. K. Rowling",
                         language="English", year=1999,
                         genre="Fantasy",
                         description="Harry Potter's THIRD year at Hogwarts",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries1)
session.add(IndividualBook3)
session.commit()

IndividualBook4 = IndividualBook(user_id=1, name="The Goblet of Fire",
                         author="J. K. Rowling",
                         language="English", year=2000,
                         genre="Fantasy",
                         description="Harry Potter's FOURTH year at Hogwarts",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries1)
session.add(IndividualBook4)
session.commit()

IndividualBook5 = IndividualBook(user_id=1, name="The Order of the Phoenix",
                         author="J. K. Rowling",
                         language="English", year=2003,
                         genre="Fantasy",
                         description="Harry Potter's FIFTH year at Hogwarts",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries1)
session.add(IndividualBook5)
session.commit()

IndividualBook6 = IndividualBook(user_id=1, name="The Half-Blood Prince",
                         author="J. K. Rowling",
                         language="English", year=2005,
                         genre="Fantasy",
                         description="Harry Potter's SIXTH year at Hogwarts",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries1)
session.add(IndividualBook6)
session.commit()

IndividualBook7 = IndividualBook(user_id=1, name="The Deathly Hallows",
                         author="J. K. Rowling",
                         language="English", year=2007,
                         genre="Fantasy",
                         description="Harry Potter's SEVENTH year at Hogwarts",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries1)
session.add(IndividualBook7)
session.commit()

# Books in PeterRabbit
bookseries2 = BookSeries(user_id=1, name="Peter Rabbit")
session.add(bookseries2)
session.commit()
# id|name| author| language| year| genre| description| bookseries_id|bookseries
IndividualBook1 = IndividualBook(user_id=1, name="Tale Of Peter Rabbit",
                         author="Beatrix Potter",
                         language="English", year=1902,
                         genre="Children's literature",
                         description="The story of mischievous and disobedient young Peter Rabbit",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries2)
session.add(IndividualBook1)
session.commit()

IndividualBook2 = IndividualBook(user_id=1, name="The Tale of Squirrel Nutkin",
                         author="Beatrix Potter",
                         language="English", year=1903,
                         genre="Children's literature",
                         description="The tale of a naughty squirrel who loses his tail.",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries2)
session.add(IndividualBook2)
session.commit()

IndividualBook3 = IndividualBook(user_id=1, name="The Tale of Benjamin Bunny",
                         author="Beatrix Potter",
                         language="English", year=1904,
                         genre="Children's literature",
                         description="The adventure of Benjamin and Peter in Mr McGregor vegetable garden",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries2)
session.add(IndividualBook3)
session.commit()
#description = "The adventure of Benjamin and Peter in Mr McGregor�s vegetable garden",
# When adding Mr McGregor's ' is giving an error: "sqlalchemy.exc.ProgrammingError: (sqlite3.ProgrammingError) You must not use 8-bit bytestrings unless you use a text_factory that can interpret 8-bit bytestrings (like text_factory = str). It is highly
# recommended that you instead just switch your application to Unicode strings."
IndividualBook4 = IndividualBook(user_id=1, name="The Tale of Two Bad Mice",
                         author="Beatrix Potter",
                         language="English", year=1905,
                         genre="Children's literature",
                         description="The mess created by two bad mice",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries2)
session.add(IndividualBook4)
session.commit()

IndividualBook5 = IndividualBook(user_id=1, name="The Tale of Mr Jeremy Fisher",
                         author="Beatrix Potter",
                         language="English", year=1906,
                         genre="Children's literature",
                         description="This tale tells of an optimistic and slightly accident-prone frog",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries2)
session.add(IndividualBook5)
session.commit()

IndividualBook6 = IndividualBook(user_id=1, name="The Story of Miss Moppet",
                         author="Beatrix Potter",
                         language="English", year=1907,
                         genre="Children's literature",
                         description="Tale of a pussy cat, Miss Moppet, chasing a mouse",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries2)
session.add(IndividualBook6)
session.commit()

# Books in TheChroniclesofNarnia
bookseries3 = BookSeries(user_id=1, name="The Chronicles of Narnia")
session.add(bookseries3)
session.commit()

IndividualBook1 = IndividualBook(user_id=1, name="The Lion, the Witch and the Wardrobe",
                         author="C. S. Lewis",
                         language="English", year=1950,
                         genre="Children's literature/ Fantasy",
                         description="Story of four ordinary children and how they discover Narnia",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries3)
session.add(IndividualBook1)
session.commit()
IndividualBook2 = IndividualBook(user_id=1, name="Prince Caspian",
                         author="C. S. Lewis",
                         language="English", year=1951,
                         genre="Children's literature/ Fantasy",
                         description="Story about how four Pevensie children help Prince Caspian in Narnia",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries3)
session.add(IndividualBook2)
session.commit()
IndividualBook3 = IndividualBook(user_id=1, name="The Voyage of the Dawn Treader ",
                         author="C. S. Lewis",
                         language="English", year=1952,
                         genre="Children's literature/ Fantasy",
                         description="Pevensie children join Prince Caspian on an voyage",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries3)
session.add(IndividualBook3)
session.commit()
IndividualBook4 = IndividualBook(user_id=1, name="The Silver Chair ",
                         author="C. S. Lewis",
                         language="English", year=1953,
                         genre="Children's literature/ Fantasy",
                         description="Prince Rilian, Caspian's son",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries3)
session.add(IndividualBook4)
session.commit()
IndividualBook5 = IndividualBook(user_id=1, name="The Horse and His Boy",
                         author="C. S. Lewis",
                         language="English", year=1954,
                         genre="Children's literature/ Fantasy",
                         description="The story follows mischievous and disobedient young Peter Rabbit",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries3)
session.add(IndividualBook5)
session.commit()
IndividualBook6 = IndividualBook(user_id=1, name="The Magician's Nephew",
                         author="C. S. Lewis",
                         language="English", year=1955,
                         genre="Children's literature/ Fantasy",
                         description="origins of Narnia - how Aslan created the world and how evil first entered it.",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries3)
session.add(IndividualBook6)
session.commit()
IndividualBook7 = IndividualBook(user_id=1, name="The Last Battle",
                         author="C. S. Lewis",
                         language="English", year=1956,
                         genre="Children's literature/ Fantasy",
                         description="This leads to the end of Narnia, revealing the true Narnia which Aslan brings them.",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries3)
session.add(IndividualBook7)
session.commit()

# Books in James Bond
bookseries4 = BookSeries(user_id=1, name="James Bond")
session.add(bookseries4)
session.commit()

IndividualBook1 = IndividualBook(user_id=1, name="Casino Royale",
                         author="Ian Fleming",
                         language="English", year=1953,
                         genre="Spy Fiction",
                         description="Story of four ordinary children and how they discover Narnia",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries4)
session.add(IndividualBook1)
session.commit()
IndividualBook2 = IndividualBook(user_id=1, name="Live and Let Die",
                         author="Ian Fleming",
                         language="English", year=1954,
                         genre="Spy Fiction",
                         description="Story of four ordinary children and how they discover Narnia",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries4)
session.add(IndividualBook2)
session.commit()
IndividualBook3 = IndividualBook(user_id=1, name="Moonraker",
                         author="Ian Fleming",
                         language="English", year=1953,
                         genre="Spy Fiction",
                         description="Will add later",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries4)
session.add(IndividualBook3)
session.commit()
IndividualBook4 = IndividualBook(user_id=1, name="Diamonds Are Forever",
                         author="Ian Fleming",
                         language="English", year=1953,
                         genre="Spy Fiction",
                         description="Will add later",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries4)
session.add(IndividualBook4)
session.commit()
IndividualBook5 = IndividualBook(user_id=1, name="From Russia, with Love",
                         author="Ian Fleming",
                         language="English", year=1953,
                         genre="Spy Fiction",
                         description="Will add later",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries4)
session.add(IndividualBook5)
session.commit()
IndividualBook6 = IndividualBook(user_id=1, name="Dr.No",
                         author="Ian Fleming",
                         language="English", year=1958,
                         genre="Spy Fiction",
                         description="Will add later",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries4)
session.add(IndividualBook6)
session.commit()
IndividualBook7 = IndividualBook(user_id=1, name="Goldfinger",
                         author="Ian Fleming",
                         language="English", year=1957,
                         genre="Spy Fiction",
                         description="Will add later",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries4)
session.add(IndividualBook7)
session.commit()
IndividualBook8 = IndividualBook(user_id=1, name="For Your Eyes Only",
                         author="Ian Fleming",
                         language="English", year=1959,
                         genre="Spy Fiction",
                         description="Will add later",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries4)
session.add(IndividualBook8)
session.commit()
IndividualBook9 = IndividualBook(user_id=1, name="Thunderball",
                         author="Ian Fleming",
                         language="English", year=1961,
                         genre="Spy Fiction",
                         description="Will add later",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries4)
session.add(IndividualBook9)
session.commit()
IndividualBook10 = IndividualBook(user_id=1, name="The Spy Who Loved Me",
                         author="Ian Fleming",
                         language="English", year=1962,
                         genre="Spy Fiction",
                         description="Will add later",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries4)
session.add(IndividualBook10)
session.commit()
IndividualBook11 = IndividualBook(user_id=1, name="On Her Majesty's Secret Service",
                         author="Ian Fleming",
                         language="English", year=1963,
                         genre="Spy Fiction",
                         description="Will add later",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries4)
session.add(IndividualBook11)
session.commit()
IndividualBook12 = IndividualBook(user_id=1, name="You Live Only Twice",
                         author="Ian Fleming",
                         language="English", year=1964,
                         genre="Spy Fiction",
                         description="Will add later",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries4)
session.add(IndividualBook12)
session.commit()
IndividualBook13 = IndividualBook(user_id=1, name="The Man with the Golden Gun",
                         author="Ian Fleming",
                         language="English", year=1965,
                         genre="Spy Fiction",
                         description="Will add later",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries4)
session.add(IndividualBook13)
session.commit()
IndividualBook14 = IndividualBook(user_id=1, name="Octopussy and The Living Daylights",
                         author="Ian Fleming",
                         language="English", year=1966,
                         genre="Spy Fiction",
                         description="Will add later",
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries4)
session.add(IndividualBook14)
session.commit()
# Books in Diary of a Wimpy Kid
bookseries5 = BookSeries(user_id=1, name="Diary of a Wimpy Kid")
session.add(bookseries5)
session.commit()

IndividualBook1 = IndividualBook(user_id=1, name="Diary of a Wimpy Kid",
                         author="Jeff Kinney",
                         language="English", year=2007,
                         genre="Realistic fiction",
                         description="""The introduction to the series
                         introduces the protagonist, Greg Heffley, his best
                         friend Rowley, his middle school problems, Halloween,
                         and the Cheese Touch.
                         """,
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries5)
session.add(IndividualBook1)
session.commit()
IndividualBook2 = IndividualBook(user_id=1, name="Rodrick Rules",
                         author="Jeff Kinney",
                         language="English", year=2008,
                         genre="Realistic fiction",
                         description="""Greg must stop Rodrick from revealing
                         the secrets that had happened last summer.
                         """,
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries5)
session.add(IndividualBook2)
session.commit()
IndividualBook3 = IndividualBook(user_id=1, name="Dog Days",
                         author="Jeff Kinney",
                         language="English", year=2009,
                         genre="Realistic fiction",
                         description="""Summer is here, but when the family
                         has not that much money to go to the beach
                         (money is tight at that time),
                         it might not be the best summer ever.
                         """,
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries5)
session.add(IndividualBook3)
session.commit()
IndividualBook4 = IndividualBook(user_id=1, name="The Ugly Truth",
                         author="Jeff Kinney",
                         language="English", year=2010,
                         genre="Realistic fiction",
                         description="""Greg is growing up, and he will have
                         to face the challenges of this period (like changing
                         dentists, and a school lock-in).
                         """,
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries5)
session.add(IndividualBook4)
session.commit()
IndividualBook5 = IndividualBook(user_id=1, name="The Cabin Fever",
                         author="Jeff Kinney",
                         language="English", year=2011,
                         genre="Realistic fiction",
                         description="""The family is stranded in the
                         house as snow begins to fall.
                         """,
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries5)
session.add(IndividualBook5)
session.commit()
IndividualBook6 = IndividualBook(user_id=1, name="The Third Wheel",
                         author="Jeff Kinney",
                         language="English", year=2012,
                         genre="Realistic fiction",
                         description="""The Valentine's Day dance is coming up,
                         and Greg has no one go with. But when Michael Sampson
                         (Abigail's date. He actually lied to her) will not be
                         going, things turn around.
                         """,
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries5)
session.add(IndividualBook6)
session.commit()
IndividualBook7 = IndividualBook(user_id=1, name="Hard Luck",
                         author="Jeff Kinney",
                         language="English", year=2013,
                         genre="Realistic fiction",
                         description="""Greg's friend count is dropping as
                         Rowley now has a girlfriend, named Abigail
                         (continuing the last book).
                         """,
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries5)
session.add(IndividualBook7)
session.commit()
IndividualBook8 = IndividualBook(user_id=1, name="The Long Haul",
                         author="Jeff Kinney",
                         language="English", year=2014,
                         genre="Realistic fiction",
                         description="""This is the family's second summer trip,
                         but instead, it's a road trip. But with the Heffleys,
                         you know what to expect from this disaster.
                         """,
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries5)
session.add(IndividualBook8)
session.commit()
IndividualBook9 = IndividualBook(user_id=1, name="Old School",
                         author="Jeff Kinney",
                         language="English", year=2015,
                         genre="Realistic fiction",
                         description="""The neighborhood is going to cut
                         electricity for the weekend, and as the family's car
                         has a fender bender, it forces Greg to go to the farm
                         trip. Will Greg survive the electricity-free days?
                         """,
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries5)
session.add(IndividualBook9)
session.commit()
IndividualBook10 = IndividualBook(user_id=1, name="Double Down",
                         author="Jeff Kinney",
                         language="English", year=2016,
                         genre="Realistic fiction",
                         description="""Greg's mom wants him to do something
                         else than video games, so he makes a movie in
                         collaboration with Rowley and joins the music program.
                         """,
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries5)
session.add(IndividualBook10)
session.commit()
IndividualBook11 = IndividualBook(user_id=1, name="Diary of a Wimpy Kid",
                         author="Jeff Kinney",
                         language="English", year=2017,
                         genre="Realistic fiction",
                         description="""The introduction to the series
                         introduces the protagonist, Greg Heffley, his best
                         friend Rowley, his middle school problems, Halloween,
                         and the Cheese Touch.
                         """,
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries5)
session.add(IndividualBook11)
session.commit()
IndividualBook12 = IndividualBook(user_id=1, name="The Gateway",
                         author="Jeff Kinney",
                         language="English", year=2018,
                         genre="Realistic fiction",
                         description="""Instead of celebrating the holidays at
                         home, Greg and his family head on an tropical vacation
                         to a resort. But what first starts as an relaxing trip,
                         later turns into a Christmas nightmare.
                         Will Greg be able to turn this vacation around?
                         """,
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries5)
session.add(IndividualBook12)
session.commit()
# "Lord Of The Rings"
bookseries6 = BookSeries(user_id=1, name="The Lord Of The Rings")
session.add(bookseries6)
session.commit()
IndividualBook1 = IndividualBook(user_id=1, name="The Fellowship of the Ring",
                         author="J. R. R. Tolkien",
                         language="English", year=1954,
                         genre="Fantasy, Adventure",
                         description="""The story begins in the Shire, where
                         the hobbit Frodo Baggins inherits the Ring from
                         Bilbo Baggins, his cousin[note 3] and guardian.
                         Neither hobbit is aware of the Ring's nature,
                         but Gandalf the Grey, a wizard and an old friend of
                         Bilbo, suspects it to be Sauron's Ring.
                         """,
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries6)
session.add(IndividualBook1)
session.commit()
IndividualBook2 = IndividualBook(user_id=1, name="The Fellowship of the Ring",
                         author="J. R. R. Tolkien",
                         language="English", year=1954,
                         genre="Fantasy, Adventure",
                         description="""The story begins in the Shire, where
                         the hobbit Frodo Baggins inherits the Ring from
                         Bilbo Baggins, his cousin[note 3] and guardian.
                         Neither hobbit is aware of the Ring's nature,
                         but Gandalf the Grey, a wizard and an old friend of
                         Bilbo, suspects it to be Sauron's Ring.
                         """,
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries6)
session.add(IndividualBook2)
session.commit()
IndividualBook3 = IndividualBook(user_id=1, name="Return Of The King",
                         author="J. R. R. Tolkien",
                         language="English", year=1955,
                         genre="Fantasy, Adventure",
                         description="""The story begins in the Shire, where
                         the hobbit Frodo Baggins inherits the Ring from
                         Bilbo Baggins, his cousin[note 3] and guardian.
                         Neither hobbit is aware of the Ring's nature,
                         but Gandalf the Grey, a wizard and an old friend of
                         Bilbo, suspects it to be Sauron's Ring.
                         """,
                         review="""This book series has been part of my
                         childhood, I can so relate to these charecters!!!""",
                         bookseries=bookseries6)
session.add(IndividualBook3)
session.commit()
print "added book series!"
