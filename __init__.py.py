from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from flask import session as login_session
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, BookSeries, IndividualBook
import random
import string
#imports for oauth2client
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
# client ID: 768079051714-7bgljeck2d6j0leh95tmnkfe999vg9l7.apps.googleusercontent.com
# client secret: F25VOhsIUave9RK1yLmOd5Nk
app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Books Catalog Application"


# Connect to Database and create database session
engine = create_engine('sqlite:///bookseries.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

@app.route('/login')
def showLogin():
    '''
    Create anti-forgery state token
    '''
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
    Gathers data from Google Sign In API and places it inside a session variable.
    """
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    code = request.data.decode('utf-8')

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        #print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

#     # Check if user exists
# user_id = getUserID(login_session['email'])
# if not user_id:
#     user_id = createUser(login_session)
#     login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    #print "done!"
    return output

# User Helper Functions

def createUser(login_session):
	newUser = User(name=login_session['username'], email=login_session[
				   'email'], picture=login_session['picture'])
	session.add(newUser)
	session.commit()
	user = session.query(User).filter_by(email=login_session['email']).one()
	return user.id


def getUserInfo(user_id):
	user = session.query(User).filter_by(id=user_id).one()
	return user


def getUserID(email):
	try:
		user = session.query(User).filter_by(email=email).one()
		return user.id
	except:
		return None



@app.route('/gdisconnect')
def gdisconnect():
    '''
    DISCONNECT - Revoke a current user's token and reset their login_session
    '''
    access_token = login_session['access_token']
    #print 'In gdisconnect access token is %s', access_token
    #print 'User name is: '
    #print login_session['username']
    if access_token is None:
 	#print 'Access Token is None'
    	response = make_response(json.dumps('Current user not connected.'), 401)
    	response.headers['Content-Type'] = 'application/json'
    	return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    #print 'result is '
    #print result
    if result['status'] == '200':
	del login_session['access_token']
    	del login_session['gplus_id']
    	del login_session['username']
    	del login_session['email']
    	del login_session['picture']
    	response = make_response(json.dumps('Successfully disconnected.'), 200)
    	response.headers['Content-Type'] = 'application/json'
    	return response
    else:

    	response = make_response(json.dumps('Failed to revoke token for given user.', 400))
    	response.headers['Content-Type'] = 'application/json'
    	return response

@app.route('/')
@app.route('/home')
def home():
    '''
    Renders static home page @ http://localhost:5000/
    '''
    return render_template('home.html')

@app.route('/about')
def about():
    '''
    Renders static about page @ http://localhost:5000/about
    '''
    return render_template('about.html')
# Show titles of book series.
@app.route('/')
@app.route('/books/')
def showBookSeries():
    '''
    Renders all the titles of the Bookseries in this catalog @ http://localhost:5000/books/
    '''
    bookseries = session.query(BookSeries).all()
    return render_template('book_titles.html', bookseries=bookseries)
# Show the indivual books in the bookseries.
# This page has the NEW/Edit/Delete functionality
@app.route('/books/<int:bookseries_id>/')
def booklist(bookseries_id):
    bookseries = session.query(BookSeries).filter_by(id=bookseries_id).first()
    individualbook = session.query(IndividualBook).filter_by(bookseries_id=bookseries.id)
    return render_template('books.html', bookseries=bookseries, items=individualbook)
# New
@app.route('/books/<int:bookseries_id>/new', methods=['GET', 'POST'])
def newIndividualBook(bookseries_id):

    if request.method == 'POST':
        newItem = IndividualBook(name=request.form['name'],
                               author=request.form['author'],
                               description=request.form['description'],
                               year=request.form['year'],
                               genre=request.form['genre'],
                               language=request.form['language'],
                               review=request.form['review'],
                               individualbook_id=individualbook_id)
        session.add(newItem)
        session.commit()
        return redirect(url_for('booklist', individualbook_id=individualbook_id))
    else:
        return render_template('newIndividualBook.html', individualbook_id=individualbook_id)
# Edit
# @app.route('/restaurants/<int:restaurant_id>/<int:menu_id>/edit',
#            methods=['GET', 'POST'])
# def editMenuItem(restaurant_id, menu_id):
#     editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
#     if request.method == 'POST':
#         if request.form['name']:
#             editedItem.name = request.form['name']
#         session.add(editedItem)
#         session.commit()
#         return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))
#     else:
#         # USE THE RENDER_TEMPLATE FUNCTION BELOW TO SEE THE VARIABLES YOU
#         # SHOULD USE IN YOUR EDITMENUITEM TEMPLATE
#         return render_template(
#             'editmenuitem.html', restaurant_id=restaurant_id, menu_id=menu_id, item=editedItem)
@app.route('/bookseries/<int:bookseries_id>/<int:individualbook_id>/edit',
            methods=['GET', 'POST'])
def editindividualbookItem(bookseries_id, individualbook_id):
    editedItem = session.query(IndividualBook).filter_by(id=individualbook_id).one_or_none()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['author']:
            editedItem.author = request.form['author']
        if request.form['language']:
            editedItem.language = request.form['language']
        if request.form['description']:
            editedItem.desciption = request.form['description']
        session.add(editedItem)
        session.commit()
        return redirect(url_for('booklist', bookseries_id=bookseries_id))
    else:
        return render_template('editindividualbookItem.html', bookseries_id=bookseries_id, individualbook_id=individualbook_id, item=editedItem)

# Delete
@app.route('/bookseries/<int:bookseries_id>/<int:individualbook_id>/delete',methods=['GET', 'POST'])
def deleteindividualbook(bookseries_id, individualbook_id):
    itemToDelete = session.query(IndividualBook).filter_by(id=individualbook_id).one_or_none()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        return redirect(url_for('booklist', bookseries_id=bookseries_id))
    else:
        return render_template('deleteindividualbook.html', item=itemToDelete)

@app.route('/register')
def register():
 return render_template('register.html')

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
