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
    '''Create anti-forgery state token'''
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
    '''Gathers data from Google Sign In API and places
    it inside a session variable.'''
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
        response = make_response(json.dumps
                ('Current user is already connected.'),200)
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
    '''DISCONNECT - Revoke a current user's token and
    reset their login_session'''
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

    	response = make_response(json.dumps
            ('Failed to revoke token for given user.', 400))
    	response.headers['Content-Type'] = 'application/json'
    	return response
# jsonify data
@app.route('/bookseries/<int:bookseries_id>/book/JSON')
def IndividualBookJSON(bookseries_id):
    bookseries = session.query(BookSeries).filter_by(id=bookseries_id).one()
    items = session.query(IndividualBook).filter_by(
        bookseries_id=bookseries_id).all()
    return jsonify(IndividualBook=[i.serialize for i in items])

@app.route('/bookseries/<int:bookseries_id>/book/<int:book_id>/JSON')
def bookItemJSON(bookseries_id, book_id):
    Book_Item = session.query(IndividualBook).filter_by(id=book_id).one()
    return jsonify(Book_Item=Book_Item.serialize)


@app.route('/bookseries/JSON')
def bookseriesJSON():
    bookseries = session.query(BookSeries).all()
    return jsonify(bookseries=[i.serialize for i in bookseries])


@app.route('/')
@app.route('/booksCatalog')
def home():
    return render_template('booksCatalog.html')

@app.route('/about')
def about():
    return render_template('about.html')

# Show titles of book series.
@app.route('/bookseries')
def showBookSeries():
    bookseries = session.query(BookSeries).all()
    return render_template('book_titles.html', bookseries=bookseries)
# ADD NEW BOOK Series
@app.route('/bookseries/new/', methods=['GET', 'POST'])
def newBookSeries():
    if request.method == 'POST':
        newBookSeries = BookSeries(name=request.form['name'])
        session.add(newBookSeries)
        session.commit()
        return redirect(url_for('showBookSeries'))
    else:
        return render_template('new_book_series.html')
# EDIT BOOK SERIES, if you change your mind click
# cancle and land on the Book Series Page
@app.route('/bookseries/<int:bookseries_id>/edit/', methods=['GET', 'POST'])
def editBookSeries(bookseries_id):
    editedBookSeries = session.query(
        BookSeries).filter_by(id=bookseries_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedBookSeries.name = request.form['name']
            return redirect(url_for('showBookSeries'))
    else:
        return render_template(
            'editBookSeries.html', bookseries=editedBookSeries)
# DELETE Book Series, if you change your mind click cancle and land
# on the Book Series Page
@app.route('/bookseries/<int:bookseries_id>/delete/', methods=['GET', 'POST'])
def deleteBookSeries(bookseries_id):
    bookSeriesToDelete = session.query(BookSeries).filter_by(id=bookseries_id).one()
    if request.method == 'POST':
        session.delete(bookSeriesToDelete)
        session.commit()
        return redirect(url_for('showBookSeries', bookseries_id=bookseries_id))
    else:
        return render_template('deleteBookSeries.html', bookseries=bookSeriesToDelete)

# Show the indivual books in the bookseries.
# This page has the NEW/Edit/Delete functionality
@app.route('/bookseries/<int:bookseries_id>/')
@app.route('/bookseries/<int:bookseries_id>/book')
def booklist(bookseries_id):
    bookseries = session.query(BookSeries).filter_by(id=bookseries_id).first()
    individualBook = session.query(IndividualBook).filter_by(bookseries_id=bookseries.id)
    return render_template('book.html', bookseries=bookseries, items=individualBook)
###ERROR
#UnboundLocalError: local variable 'newBookItem' referenced before assignment

@app.route('/bookseries/<int:bookseries_id>/book/new/', methods=['GET', 'POST'])
def newBookItem(bookseries_id):
    if request.method == 'POST':
        newBookItem = IndividualBook(name=request.form['name'],
            author=request.form['author'],
            language=request.form['language'],
            description=request.form['description'],
            bookseries_id=bookseries_id)
        session.add(newBookItem)
        session.commit()
        return redirect(url_for('booklist', bookseries_id=bookseries_id))
    else:
        return render_template('new_individual_book.html', bookseries_id=bookseries_id, item=newBookItem)

@app.route('/bookseries/<int:bookseries_id>/book/<int:book_id>/edit',methods=['GET', 'POST'])
def editBookItem(bookseries_id, book_id):
    editedBookItem = session.query(IndividualBook).filter_by(id=book_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedBookItem.name = request.form['name']
        if request.form['author']:
            editedBookItem.author = request.form['author']
        if request.form['language']:
            editedBookItem.language = request.form['language']
        if request.form['discription']:
            editedBookItem.discription = request.form['discription']
        session.add(editedBookItem)
        session.commit()
        return redirect(url_for('booklist', bookseries_id=bookseries_id))
    else:
        return render_template('edit_individual_bookitem.html',bookseries_id=bookseries_id, item=editedBookItem)

# Delete BOOK
@app.route('/bookseries/<int:bookseries_id>/book/<int:book_id>/delete',methods=['GET', 'POST'])
def deleteBookItem(bookseries_id, book_id):
    itemToDelete = session.query(IndividualBook).filter_by(id=book_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        return redirect(url_for('booklist', bookseries_id=bookseries_id))
    else:
        return render_template('delete_individualbook.html',bookseries_id=bookseries_id, book_id=book_id, item=itemToDelete)
#Add new user sign up!
@app.route('/register')
def register():
 return render_template('register.html')

if __name__ == '__main__':
    app.secret_key = 'super_SECRET_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
