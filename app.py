from flask import Flask, render_template, request, make_response, url_for, flash, redirect, session, abort, jsonify,g

from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from Forms import LoginForm, RegistrationForm
from index import app, db, mongo,logger
from models import Community, User
import json
import psycopg2
import os
import sys
import datetime
from index import app, db, mongo,logger
from models import Community, User
import  myexception
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()
import pprint

app = Flask(__name__)

Bootstrap(app)
app.config['SECRET_KEY'] = os.urandom(32)


# @app.route('/signup', methods=['GET','POST'])
# def signup():
#     form = RegisterForm()
#     if form.validate_on_submit():
#         return '<h1>'+form.username.data+' '+form.password.data+'</h2>'
#     return render_template('signup.html',form=form)

#create new community
@app.route('/new_community', methods = ['POST'])
def new_community():
    if not request.json or not 'name' in request.json or not 'address' in request.json or not 'city' in request.json or not 'zip_code' in request.json:
        abort(400)
    logger.debug("Received Request by user %s", request.json)
    name = request.json['name']
    address = request.json['address']
    city = request.json['city']
    zip_code = request.json['zip_code']
    creation_date = datetime.datetime.now()
    com = Community(name = name, address = address,
    city = city,
    zip_code = zip_code,
    creation_date = creation_date)
    db.session.add(com)
    db.session.commit()
    return "Community " + name + " added."

#create new user
@app.route('/sign_up', methods = ['GET','POST'])
def new_user():
    form = RegistrationForm()
    if request.method == 'GET':
        return render_template('signup.html',form=form)
    # if not request.json or not "contact_number" in request.json or not "username" in request.json or not "communityID" in request.json or not "email" in request.json or not "password" in request.json:
    #     abort(400)
    username = request.json['username']
    communityID = request.json['communityID']
    firstName = request.json['firstName']
    lastName = request.json['lastName']
    email = request.json['email']
    password = request.json['password']
    contact_number = request.json['contact_number']
    # if username == '' or password == '':
    #     raise myexception.Unauthorized("Please enter username and password", 401)
    # elif User.query.filter_by(username = username).first() is not None:
    #     raise myexception.UserExists("User Already exists", 402)
    # else:
    user = User(username = username, communityID = communityID,
    firstName = firstName, lastName=lastName,
    email = email, contact_number = contact_number)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return "User " + firstName + " added."

@app.route('/login', methods=['POST'])
def authenticate():
    # if session['logged_in'] == False:
    username = request.json['username']
    password = request.json['password']
    if username is None or password is None:
        # raise myexception.Unauthorized("Please enter username and password", 401)
        return ("Please enter username and/or password")
        # abort(400)  # missing arguments
    elif User.query.filter_by(username=username).first() is not None:
        verify_password(username,password)
        if session['logged_in'] == True:
            return ("Access Granted and logged in")

@auth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(username = username).first()
    if not user or not user.verify_password(password):
        # raise myexception.Unauthorized("Invalid username or password", 401)
        return ("Invalid username or password")
        # return False
    g.user = user
    session['logged_in'] = True
    # raise myexception.Unauthorized("Access Granted and logged in", 200)
    # return ("Access Granted and logged in")

#add new post
@app.route('/add_post', methods = ['POST'])
def add_post():
    posts = mongo.posts
    post_data = {
        'title': request.json['title'],
        'content': request.json['content'],
        'author': request.json['author'],
        'attachment': request.json['attachment'],
        'posted_date': datetime.datetime.now(),
        'comments': []
    }
    result = posts.insert_one(post_data)
    return ('One post: {0}'.format(result.inserted_id))

#add comment to a post
@app.route('/add_post_comment', methods = ['POST'])
def add_post_comment():
    mongo.posts.update_one(
    {"_id": request.json['_id']},
    {"$push": {
        'comments': {
            'author': { 'name': request.json['name']},
                    'posted': datetime.datetime.now(),
                    'text': request.json['text']
                }
            }
        }
    )
    return ("Comment Added to post " + str(request.json['_id']))

#add message
@app.route('/add_message', methods = ['POST'])
def add_message():
    messages = mongo.messages
    message_data = {
        'fromCommunityID': request.json['fromCommunityID'],
        'fromUserId':request.json['fromUserId'],
        'subject': request.json['subject'],
        'content': request.json['content'],
        'toUserId': request.json['toUserId'],
        'toCommunityId': request.json['toCommunityId'],
        'message_date': datetime.datetime.now()
    }
    result = messages.insert_one(message_data)
    return ('One message: {0}'.format(result.inserted_id))

#add complaint
@app.route('/add_complaint', methods = ['POST'])
def add_complaint():
    complaints = mongo.complaints
    complaint_data = {
        'communityID': request.json['communityID'],
        'category': request.json['category'],
        'title': request.json['title'],
        'content': request.json['content'],
        'complainee': request.json['complainee'],
        'posted_date': datetime.datetime.now(),
        'status':request.json['status']
    }
    result = complaints.insert_one(complaint_data)
    return ('One complaint: {0}'.format(result.inserted_id))

#get all the distict communities
@app.route('/get_all_community', methods = ['GET'])
def get_all_community():
    communities = Community.query.all()
    communities_name = [community.name for community in communities]
    return json.dumps(communities_name)

@app.route('/')
def home():
    return render_template('userdashboard.html')

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        return redirect(url_for('home'))
    return render_template('login.html',form=form)

if __name__ == '__main__':
    app.run(debug = True,threaded=True)
