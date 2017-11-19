from flask import Flask, render_template, request, make_response, url_for, flash, redirect, session, abort, jsonify,g

from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from Forms import LoginForm, RegistrationForm, commuityRegistraion
from index import app, db, mongo,logger
from models import Community, User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
import json
import psycopg2
import os
import sys
import datetime
from index import app, db, mongo,logger
from models import Community, User, UserCommunity, UserModerator
import  myexception
from flask_httpauth import HTTPBasicAuth
from awsServices import send_email, sendMessage

auth = HTTPBasicAuth()
import pprint

app = Flask(__name__)

Bootstrap(app)
app.config['SECRET_KEY'] = os.urandom(32)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_message = "You should be logged in to view this page"
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(username):
    # print username
    return User.query.get(username)


#Test Route
@app.route('/test', methods = ['GET','POST'])
def test():
    return render_template('newCommunity.html')



#create new community
@app.route('/new_community', methods = ['GET','POST'])
@login_required
def new_community():
    form = commuityRegistraion()
    if form.validate_on_submit():
        name = form.name.data.lower()
        desc = form.desc.data
        address = form.address.data
        city = form.city.data
        zip_code = form.zip_code.data
        creation_date = datetime.datetime.now()
        created_by = current_user.username
        com = Community(name=name,
                        description=desc,
                        address=address,
                        city=city,
                        zip_code=zip_code,
                        creation_date=creation_date,
                        created_by = created_by)
        if Community.query.filter_by(name=name).first() is not None:
            flash("Community name already exists")
            form = commuityRegistraion()
            return render_template('newCommunity.html',form=form)
        db.session.add(com)
        db.session.commit()
        return '<h1>New Community is created</h1>'
    return render_template('newCommunity.html',form=form)

#create new user
@app.route('/sign_up', methods = ['GET','POST'])
def new_user():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data.lower()
        firstName = form.firstname.data
        lastName = form.lastname.data
        email = form.email.data
        hashed_password = generate_password_hash(form.password.data,method='sha256')
        password = hashed_password
        contact_number = form.contact.data
        new_user = User(username = username,
                        firstName = firstName,
                        lastName=lastName,
                        email = email,
                        password=password,
                        contact_number = contact_number)
        if User.query.filter_by(username=username).first() is not None:
            flash("Username already exists")
            form = RegistrationForm()
            return render_template('signup.html', form=form)
        elif User.query.filter_by(email=email).first() is not None:
            flash("Email already registered")
            form = RegistrationForm()
            return render_template('signup.html', form=form)
        db.session.add(new_user)
        db.session.commit()
        return '<h1>New user has been created</h1>'
    return render_template('signup.html', form=form)

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

@app.route('/home')
@login_required
def home():
    # print (current_user.username)
    return render_template('userdashboard.html')

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.rememberMe.data)
                session['loggedIn'] = True
                session['username'] = user.username
                return redirect(url_for('home'))
    return render_template('login.html',form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have successfully been logged out.')
    session['loggedIn'] = False
    return redirect(url_for('login'))

def getListOfCommunities():
    communities = Community.query.all()
    communities_name = [community.name for community in communities]
    return [(k,v) for k,v in enumerate(communities_name)]

def getCommunityId(communityName):
    communityObj = Community.query.filter_by(name = communityName).first()
    return communityObj.ID

#get users in a community
@app.route('/get_community_users', methods = ['POST'])
@login_required
def getCommunityUsers():
    communityName = request.json['communityName'].lower()
    communityObj = Community.query.filter_by(name = communityName).first()
    communityUsers = UserCommunity.query.filter_by(communityID=communityObj.ID)
    users_list = []
    for item in communityUsers.all():
        users_list.append(item.userID)
    return json.dumps(users_list)

#get users in a community
@app.route('/get_community_list', methods = ['GET'])
@login_required
def getCommunityList():
    communities = Community.query.all()
    communities_name = [community.name for community in communities]
    return json.dumps(communities_name)

@app.route('/get_requested_community', methods = ['GET'])
def getRequestedCommunity():
    communityObj = Community.query.filter_by(status = 'requested').all()
    communityList = []
    for item in communityObj:
        communityList.append(item.name)
    return json.dumps(communityList)

@app.route('/approve_community', methods = ['POST'])
def approveCommunity():
    communityName = request.json['name'].lower()
    communityDetails = Community.query.filter_by(name = communityName).first()
    communityID = communityDetails.ID
    created_by = communityDetails.created_by
    user_comm = UserCommunity(userID=created_by,
                        communityID=communityID)
    user_mod = UserModerator(communityID=communityID,
    moderator=created_by)
    communityDetails.status = 'Approved'
    db.session.add(user_comm)
    db.session.add(user_mod)
    db.session.commit()
    return '<h1>Community Approved</h1>'

@app.route('/add_member', methods = ['POST'])
def addCommunityMember():
    userID = current_user.username
    communityName = request.json['name']
    communityID = Community.query.filter_by(name = communityName).first()
    user_comm = UserCommunity(userID=userID,
                        communityID=communityID)
    db.session.add(user_comm)
    db.session.commit()
    return '<h1>Member Added</h1>'

@app.route('/delete_community', methods = ['POST'])
def deleteCommunity():
    communityName = request.json['name']
    communityID = Community.query.filter_by(name = communityName).first()
    db.session.delete(communityID)
    db.session.commit()


#post according to user
#post acc. to community
#message inbox user
#message sent user

if __name__ == '__main__':
    app.run(debug = True,threaded=True)
