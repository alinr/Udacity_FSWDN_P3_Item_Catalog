import os
import base64

from functools import wraps
from datetime import datetime

from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from flask import session as login_session
from flask import make_response
from werkzeug.exceptions import NotFound

from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Item, Category


import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

import httplib2
import json
import requests

app = Flask(__name__)



GOOGLE_CLIENT_ID = json.loads(
    open('google_client_secrets.json', 'r').read())['web']['client_id']
FACEBOOK_APP_ID = json.loads(
    open('fb_client_secrets.json', 'r').read())['web']['app_id']
APPLICATION_NAME = "Item Catalog Application"



# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect(url_for('showLogin', next=request.url))
        return f(*args, **kwargs)
    return decorated_function



# Testing
# ToDo: Delete this function
@app.route('/user')
def user():
    users = session.query(User).all()

    content = ""
    for user in users:
        content += user.email
        content += ", "
    return content



@app.route('/')
def home():
    """Homepage: lists the items which were recently added
     in descending order (newest item first)."""
    categories = session.query(Category).all()
    items = session.query(Item).order_by(desc(Item.created_on)).limit(10).all()
    return render_template('home.html', categories=categories, items=items)


@app.route('/category/<int:category_id>/')
def showCategory(category_id):
    """ List all items of one category
    Args:
        category_id: the id of the category
    """
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    return render_template('showCategory.html', categories=categories,
                           category=category, items=items,
                           count_items=len(items), category_id=category_id)


@app.route('/category/<int:category_id>/item/<int:item_id>/')
def showItem(category_id, item_id):
    """ List all items of one category
    Args:
    category_id: the id of the category
    item_id: the id of the item
    """
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    return render_template('showItem.html', categories=categories,
                           category=category, item=item)


# Edit routes for categories
@app.route('/category/new/', methods=['GET', 'POST'])
@login_required
def newCategory():
    """ Create new category """
    if request.method == 'POST':
        newCategory = Category(name=request.form['category_name'])
        session.add(newCategory)
        flash('New Category %s successfully created' % newCategory.name)
        session.commit()
        return redirect(url_for('home'))
    else:
        return render_template('forms/newCategory.html')


@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
@login_required
def editCategory(category_id):
    """ Edit category
     Args:
        category_id: the id of the category
    """

    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=category_id).one()

    if request.method == 'POST':

        nonce = request.form['nonce'].strip()

        # Check if nonce is set correct
        if not useNonce(nonce):
            flash("An error occurred. Please try again.", "danger")
            return render_template('forms/editCategory.html',
                                   categories=categories,
                                   category=category,
                                   nonce=createNonce())

        category.name = request.form['category_name'].strip()
        category.description = request.form['category_description'].strip()
        session.add(category)
        flash('Category %s successfully updated.' % category.name)
        session.commit()
        return redirect(url_for('home'))
    else:
        return render_template('forms/editCategory.html',
                               categories=categories,
                               category=category,
                               nonce=createNonce())


@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_id):
    """ Delete category
     Args:
        category_id: the id of the category
    """

    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=category_id).one()

    if request.method == 'POST':

        nonce = request.form['nonce'].strip()

        # Check if nonce is set correct
        if not useNonce(nonce):
            flash("An error occurred. Please try again.", "danger")
            return render_template('forms/deleteCategory.html',
                                   categories=categories,
                                   category=category,
                                   nonce=createNonce())

        session.delete(category)
        flash('%s Successfully Deleted' % category.name)
        session.commit()
        return home()
    else:
        return render_template('forms/deleteCategory.html',
                               categories=categories,
                               category=category,
                               nonce=createNonce())


# Edit routes for items
@app.route('/item/new/', methods=['GET', 'POST'])
@app.route('/item/new/category/<int:category_id>', methods=['GET', 'POST'])
@login_required
def newItem(category_id=''):
    """ Create new item
    Args:
        category_id: (optional) the id of the category
    """

    categories = session.query(Category).all()

    if request.method == 'POST':

        nonce = request.form['nonce'].strip()

        # Check if nonce is set correct
        if not useNonce(nonce):
            flash("An error occurred. Please try again.", "danger")
            return render_template('forms/newItem.html',
                                   categories=categories, nonce=createNonce())

        # Check if a name is set
        if not request.form['item_name'].strip():
            flash("Please enter a name", "danger")
            return render_template('forms/newItem.html',
                                   categories=categories, nonce=createNonce())

        # Check if a category is selected
        if not request.form['item_category'].strip():
            flash("Please enter a name", "danger")
            return render_template('forms/newItem.html',
                                   categories=categories, nonce=createNonce())

        try:
            category = session.query(Category).filter_by(
                id=request.form['item_category'].strip()).one()
        except Exception, e:
            flash("Please choose a valid category.", "danger")
            return render_template('forms/newItem.html',
                                   categories=categories, nonce=createNonce())

        # check if an items with the same name already exists in this category
        existingItem = session.query(Item).filter_by(
            category_id=category.id, name=request.form['item_name'].strip()).first()
        if existingItem:
            flash("An item with the same name already exists "
                  "in this category. Please choose a different name", "danger")
            return render_template('forms/newItem.html',
                                   categories=categories, nonce=createNonce())


        picture = request.files['item_picture']
        picture_data = None

        if picture:
            if not allowed_file(picture.filename):
                flash("The picture must be a JPEG, GIF, or PNG file.", "danger")
                return render_template('forms/newItem.html',
                                       categories=categories,
                                       nonce=createNonce())

            picture_data = picture.read()

        newItem = Item(name=request.form['item_name'],
                       description=request.form['item_description'],
                       category_id=request.form['item_category'],
                       user_id=login_session['user_id'],
                       created_on=datetime.utcnow())

        if picture_data:
            newItem.picture = picture.filename
            newItem.picture_data = picture_data


        session.add(newItem)
        session.commit()
        flash('New Item %s successfully created' % newItem.name)
        session.commit()
        return redirect(url_for('home'))
    else:
        if category_id != '':
            return render_template('forms/newItem.html',
                                   category_id=category_id,
                                   categories=categories,
                                   nonce=createNonce())
        else:
            return render_template('forms/newItem.html',
                                   categories=categories,
                                   nonce=createNonce())


@app.route('/item/<int:item_id>/edit/', methods=['GET', 'POST'])
@login_required
def editItem(item_id):
    """ Edit item
    Args:
        item_id: the id of the item which shall be edited
    """
    categories = session.query(Category).all()
    item = session.query(Item).get(item_id)

    # Check if item is property of the logged in user
    if item.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not " \
               "authorized to edit this item. Please create your " \
               "own item in order to delete.');}</script>" \
               "<body onload='myFunction()''>"


    if request.method == 'POST':

        nonce = request.form['nonce'].strip()

        # Check if nonce is set correct
        if not useNonce(nonce):
            flash("An error occurred. Please try again.", "danger")
            return render_template('forms/newItem.html',
                                   categories=categories,
                                   nonce=createNonce())

        # Check if a name is set
        if not request.form['item_name'].strip():
            flash("Please enter a name", "danger")
            return render_template('forms/newItem.html',
                                   categories=categories,
                                   nonce=createNonce())

        # Check if a category is selected
        if not request.form['item_category'].strip():
            flash("Please enter a name", "danger")
            return render_template('forms/newItem.html',
                                   categories=categories,
                                   nonce=createNonce())

        try:
            category = session.query(Category).filter_by(
                id=request.form['item_category'].strip()).one()
        except Exception, e:
            flash("Please choose a valid category.", "danger")
            return render_template('forms/newItem.html',
                                   categories=categories,
                                   nonce=createNonce())

        removeExistingPicture = request.form['removeExistingPicture'].strip().lower()

        # Remove picture
        if removeExistingPicture == "true":
            item.picture = None
            item.picture_data = None

        picture = request.files['item_picture']
        picture_data = None

        if picture:
            if not allowed_file(picture.filename):
                flash("The picture must be a JPEG, GIF or PNG file.", "danger")
                return render_template('edit_item.html',
                                       categories=categories,
                                       item=item,
                                       nonce=createNonce())

            picture_data = picture.read()
            print "Content-Length: %s" % picture.content_length

        item.name = request.form['item_name'].strip()
        item.description = request.form['item_description'].strip()
        item.category = category

        if picture_data:
            item.picture = picture.filename
            item.picture_data = picture_data

        session.add(item)
        session.commit()
        flash('Item %s successfully edited' % item.name)
        session.commit()
        return redirect(url_for('home'))
    else:
        return render_template('forms/editItem.html',
                               categories=categories,
                               item=item,
                               nonce=createNonce())


@app.route('/item/<int:item_id>/delete/', methods=['GET', 'POST'])
@login_required
def deleteItem(item_id):
    """ Delete item
    Args:
        item_id: the id of the item
    """

    categories = session.query(Category).all()
    itemToDelete = session.query(
        Item).filter_by(id=item_id).one()

    # Check if item is property of the logged in user
    if itemToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not " \
               "authorized to delete this item. Please create your " \
               "own item in order to delete.');}</script>" \
               "<body onload='myFunction()''>"

    if request.method == 'POST':
        nonce = request.form['nonce'].strip()
        # Check if nonce is set correct
        if not useNonce(nonce):
            flash("An error occurred. Please try again.", "danger")
            return render_template('forms/newItem.html',
                                   categories=categories,
                                   nonce=createNonce())

        session.delete(itemToDelete)
        flash('%s Successfully Deleted' % itemToDelete.name)
        session.commit()
        return home()
    else:
        return render_template('forms/deleteItem.html',
                               item=itemToDelete,
                               categories=categories,
                               nonce=createNonce())


# Picture functionality
def allowed_file(filename):
    """ Check if image type is allowed
    Args:
        filename: name of the (image) file
    Returns:
        file extension of the uploaded file
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() \
           in ['jpg', 'jpeg', 'png', 'gif']


@app.route('/item/<int:item_id>/picture/')
def itemPicture(item_id):
    """ Get the image for a given item
    Args:
        item_id: id of the item
    Returns:
        image for the item
    """
    item = session.query(Item).get(item_id)

    if not item.picture:
        raise NotFound()

    file_extension = item.picture.rsplit('.', 1)[1].lower()

    if file_extension == "jpg" or file_extension == "jpeg":
        content_type = "image/jpeg"
    elif file_extension == "png":
        content_type = "image/png"
    elif file_extension == "gif":
        content_type = "image/gif"

    return item.picture_data, 200, {
        'Content-Type': content_type,
        'Content-Disposition': "filename='%s'" % item.picture}


# JSON Routes
@app.route('/category/<int:category_id>/JSON')
def categoryJSON(category_id):
    """ Show JSON of all items of one category """
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/category/<int:category_id>/item/<int:item_id>/JSON')
def itemJSON(category_id, item_id):
    """ Show JSON of one category """
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=item.serialize)


@app.route('/categories/JSON')
def categoriesJSON():
    """ Show JSON of all categories """
    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])


# XML Routes
@app.route('/categories/XML')
def categoriesXML():
    """Returns the categories as XML document."""
    categories = session.query(Category).all()

    content = []
    content.append('<?xml version="1.0" encoding="UTF-8"?>')
    content.append("<Categories>")
    for category in categories:
        category.serializeToXml(content)
    content.append("</Categories>")

    return str.join("\n", content), 200, {'Content-Type': 'text/xml'}


@app.route('/category/<int:category_id>/XML')
def categoryXML(category_id):
    """ Show XML of items of one category """
    items = session.query(Item).filter_by(category_id=category_id).all()

    content = []
    content.append('<?xml version="1.0" encoding="UTF-8"?>')
    content.append("<Items>")
    for item in items:
        item.serializeToXml(content)
    content.append("</Items>")

    return str.join("\n", content), 200, {'Content-Type': 'text/xml'}


@app.route('/category/<int:category_id>/item/<int:item_id>/XML')
def itemXML(category_id, item_id):
    """ Show XML of one item """
    item = session.query(Item).filter_by(id=item_id).one()

    content = []
    content.append('<?xml version="1.0" encoding="UTF-8"?>')
    item.serializeToXml(content)

    return str.join("\n", content), 200, {'Content-Type': 'text/xml'}


# User Helper Functions
def createUser(login_session):
    """ Create an user
    Args:
        login_session: saved information about the user in a session
    Returns:
        User ID
    """
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """ Call an user by ID
    Args:
        user_id: user's id
    Returns:
        Object user
    """
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """ Call an user by email
    Args:
        email: user's email
    Returns:
        User ID
    """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Login functionality
@app.route('/login')
def showLogin():
    """ Crate login functionality """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state

    return render_template('login.html', STATE=state,
                           GOOGLE_CLIENT_ID=GOOGLE_CLIENT_ID,
                           FACEBOOK_APP_ID=FACEBOOK_APP_ID)


# Facebook login functionality
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    """ Login functionality via Facebook API """
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=' \
          'fb_exchange_token&client_id=%s&client_secret=%s' \
          '&fb_exchange_token=%s' % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.2/me"
    # strip expire tag from access token
    token = result.split("&")[0]


    url = 'https://graph.facebook.com/v2.2/me?%s&fields=name,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)

    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to
    # properly logout, let's strip out the information before the
    # equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.2/me/picture?%s' \
          '&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;' \
              '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


# Google Plus Login functionality
@app.route('/gconnect', methods=['POST'])
def gconnect():
    """ Login functionality via Google Plus API """

    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('google_client_secrets.json', scope='')
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

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != GOOGLE_CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;' \
              'border-radius: 150px;-webkit-border-radius: ' \
              '150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# Logout based on provider
@app.route('/logout')
def logout():
    """ Logout functionality """
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('home'))
    else:
        flash("You were not logged in")
        return redirect(url_for('home'))


# Facebook disconnect
@app.route('/fbdisconnect')
def fbdisconnect():
    """ Disconnect user from Facebook-Login """
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?' \
          'access_token=%s' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Google Plus disconnect
@app.route('/gdisconnect')
def gdisconnect():
    """ Disconnect user from Google-Plus-Login """
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


def createNonce():
    """Creates a new nonce and stores it in the session."""
    nonce = base64.b64encode(os.urandom(32))
    login_session['nonce'] = nonce

    return nonce


def useNonce(nonce):
    """Compares the provided nonce with the one stored in the session.
    If a nonce is stored in the session it will be removed even if the
    nonces should not match.
    Args:
        nonce: the nonce which was included in the post request
    Returns:
        True in case the provided nonce is equal to the nonce stored
        in the session, otherwise False
    """
    try:
        session_nonce = login_session['nonce']
        if not session_nonce:
            return False

        del(login_session['nonce'])

        if not nonce:
            return False

        if nonce != session_nonce:
            return False

        return True
    except Exception:
        return False








if __name__ == '__main__':
    app.secret_key = '9.~-8ggBlP1p;AU6}9.}4#PE l|~M{7;gdM4Coxx/[.YS`<~+J:P&$_ik[|a yXS'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
