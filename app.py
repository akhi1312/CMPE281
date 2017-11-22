from flask import Flask, render_template, request, make_response, url_for, flash, redirect, session, abort, jsonify,g

from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from Forms import LoginForm, RegistrationForm, commuityRegistraion, ArticleForm ,EditForm
from index import app, db, mongo,logger
from models import Community, User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
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
    return render_template('admin.html')

@app.route('/',methods = ['GET'])
def index():
    return render_template('index.html')

@app.route('/admin', methods = ['GET'])
def admin():
    return render_template('admin.html')

@app.route('/admin_users', methods = ['GET','POST'])
def admin_users():
    return render_template('admin_users.html')

@app.route('/admin_community', methods = ['GET','POST'])
def admin_community():
    return render_template('admin_community.html')

@app.route('/admin_post', methods = ['GET','POST'])
def admin_post():
    return render_template('admin_post.html')

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
        message = 'Hi Admin, This is to inform that '+current_user.username+' has created a new commmunity named as '+name+'. User email is '+ current_user.email +' . Please Approve it.'
        subject = 'New Community '+ name + ' acceptance mail.'
        # send_email(message, subject)
        # sendMessage(current_user.contact_number,current_user.username, name)
        flash('Community ' + name + 'has been created. Waiting for admin approval.' )
        return redirect(url_for('home'))
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
        joining_date = datetime.datetime.now()
        new_user = User(username = username,
                        firstName = firstName,
                        lastName=lastName,
                        email = email,
                        password=password,
                        contact_number = contact_number,
                        joining_date=joining_date)
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
        flash('Registration has been done successfully. Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

#add new post
@app.route('/add_post', methods = ['POST'])
# def add_post(category,title,content):
def add_post():
    posts = mongo.posts
    post_data = {
        'category':request.json['category'].lower(),
        'title': request.json['title'],
        'content': request.json['content'],
        # 'category':category.lower(),
        # 'title': title,
        # 'content': content,
        'author': current_user.username,
        'posted_date': datetime.datetime.now(),
        'comments': []
    }
    result = posts.insert_one(post_data)
    return ('One post: {0}'.format(result.inserted_id))

@app.route('/messages',methods=['GET'])
def messages():
    return render_template('messages.html')

@app.route('/joincommunity',methods=['GET'])
def listOfCommunitites():
    joinedCommunities = getCommunityDetailsJoined()
    unjoinedCommunities = getCommunityDetailsUnjoined()
    return render_template('joincommunity.html',joined = joinedCommunities, unjoined = unjoinedCommunities)


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
        'fromUserId':request.json['fromUserId'],
        'subject': request.json['subject'],
        'content': request.json['content'],
        'toUserId': request.json['toUserId'],
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

@app.route('/home',methods = ['GET','POST'])
@login_required
def home():
    categories = getUserCommunities()
    categories.append((0,'General'))
    form = ArticleForm(categories)
    display_posts = getPostsByUser()
    communities = getUserCommunities()
    # print (communities)
    # print communities
    if form.validate_on_submit():
        title = form.title.data
        # body = form.body.data.split('<p>')[1].split('</p>')[0]
        body = form.body.data
        category = dict(categories).get(form.category.data)
        add_post(category,title,body)
        form.title.data = ""
        form.body.data = ""
        form.category.data = ""
        display_posts = getPostsByUser()
    return render_template('userdashboard.html',form=form, posts = display_posts, communities = communities)




@app.before_request
def before_request():
    g.user = current_user


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    username = session['username']
    userposts = mongo.posts.find({ "author": username })
    user = User.query.filter_by(username=username).first()

    form = EditForm(request.form)
    if form.validate_on_submit():
        print ("Inside User Updated")
        user.email = form.email.data
        user.contact_number = form.contact.data
        user.firstName = form.firstname.data
        user.lastName = form.lastname.data
        db.session.commit()
        print ("User Updated")
        flash('Your changes have been saved.')
        return redirect(url_for('profile'))
    else:
        form.email.data = user.email
        form.contact.data = user.contact_number
        form.firstname.data = user.firstName
        form.lastname.data = user.lastName
        print ("Inside else User Updated")
    return render_template('profile.html', form=form , userposts = userposts)

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
            else:
                flash('password is incorrect')
        else:
            flash('User is not registered')
    return render_template('login.html',form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have successfully been logged out.')
    session['loggedIn'] = False
    return redirect(url_for('login'))

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

#get list of approved communities
@app.route('/get_community_list', methods = ['GET'])
@login_required
def getCommunityList():
    communities = Community.query.filter_by(status = 'Approved').all()
    communities_name = [community.name for community in communities]
    return json.dumps(communities_name)

#get list of requested communitites
@app.route('/get_requested_community', methods = ['GET'])
def getRequestedCommunity():
    communityObj = Community.query.filter_by(status = 'requested').all()
    communityList = []
    for item in communityObj:
        communityList.append(item.name)
    return json.dumps(communityList)

#api to approve a requested community
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

#api to join a community
@app.route('/join_community', methods = ['POST'])
def joinCommunity():
    userID = current_user.username
    # communityID = request.json['id']
    communityID = request.form['id']
    # print (communityID.ID)
    user_comm = UserCommunity(userID=userID,
                        communityID=communityID)
    db.session.add(user_comm)
    db.session.commit()

    # return '<h1>Member Added</h1>'
    communityName = (Community.query.filter_by(ID=communityID).first()).name
    message = 'Hi Moderator, This is to inform that '+current_user.username+' has joined '+communityName+' community. User email is '+ current_user.email +' .'
    subject = 'New Member Joined to '+ communityName + ' community.'
    # send_email(message, subject)
    data = {
        'status':200
    }
    return json.dumps(data)

#api to join a community
@app.route('/leave_community', methods = ['POST'])
def leaveCommunity():
    userID = current_user.username
    communityID = request.form['id']
    # communityID = request.json['communityID']
    UserCommunity.query.filter_by(communityID=communityID, userID=userID).delete()
    db.session.commit()
    communityName = (Community.query.filter_by(ID=communityID).first()).name
    message = 'Hi Moderator, This is to inform that '+current_user.username+' has left '+communityName+' community. User email is '+ current_user.email +' .'
    subject = 'Member left '+ communityName + ' community.'
    # send_email(message, subject)
    data = {
        'status':200
    }
    return json.dumps(data)

#api to get communities a user is member of
# @app.route('/user_community', methods = ['GET'])
def getUserCommunities():
    communities = UserCommunity.query.filter_by(userID=current_user.username).all()
    communityNames = []
    ids = []
    for item in communities:
        communityNames.append((Community.query.filter_by(ID=item.communityID).first()).name)
        ids.append((Community.query.filter_by(ID=item.communityID).first()).ID)
    return [(k,v) for k,v in zip(ids, communityNames)]

#api to get full community details for a joined user community
@app.route('/user_joined_community', methods = ['GET'])
def getCommunityDetailsJoined():
    communities = UserCommunity.query.filter_by(userID=current_user.username).all()
    communityObj = []
    moderators = []
    response = []
    users = []
    for community in communities:
        x = UserCommunity.query.filter_by(communityID = community.communityID).all()
        users.append(len(x))
        communityObj.append(Community.query.filter_by(ID = community.communityID).first())
        moderators.append(UserModerator.query.filter_by(communityID = community.communityID).first().moderator)
    for obj in communityObj:
        data = {
        "id" : obj.ID,
        "name" : obj.name,
        "creation_date" : str(obj.creation_date).split(" ")[0],
                }
        response.append(data)
    for i in range(0,len(moderators)):
        response[i]['moderator'] = moderators[i]
        response[i]['users'] = users[i]
    # return json.dumps(response)
    return response
    # print (communities)

#api to get full community details for a unjoined user community
@app.route('/user_unjoined_community', methods = ['GET'])
def getCommunityDetailsUnjoined():
    communities = UserCommunity.query.filter_by(userID=current_user.username).all()
    totalCommunities = Community.query.filter_by(status = 'Approved').all()
    jid = set()
    tid = set()
    for community in communities:
        jid.add(community.communityID)
    for community in totalCommunities:
        tid.add(community.ID)
    unjoined =  tid - jid
    moderators = []
    response = []
    communityObj = []
    users = []
    for id in unjoined:
        x = UserCommunity.query.filter_by(communityID = id).all()
        users.append(len(x))
        communityObj.append(Community.query.filter_by(ID = id).first())
        moderators.append(UserModerator.query.filter_by(communityID = id).first().moderator)
    for obj in communityObj:
        data = {
        "id" : obj.ID,
        "name" : obj.name,
        "creation_date" : str(obj.creation_date).split(" ")[0],
                }
        response.append(data)
    for i in range(0,len(moderators)):
        response[i]['moderator'] = moderators[i]
        response[i]['users'] = users[i]
    # return json.dumps(response)
    return response

#api to delete a community
@app.route('/delete_community', methods = ['POST'])
def deleteCommunity():
    communityName = request.json['name']
    communityID = Community.query.filter_by(name = communityName).first()
    db.session.delete(communityID)
    db.session.commit()

#api to get posts filter by user
@app.route('/get_user_posts', methods = ['GET'])
def getPostsByUser():
    userID = current_user.username
    communities = UserCommunity.query.filter_by(userID=userID).all()
    posts = mongo.posts
    generalPosts = []
    communityPosts = []
    communityNames = []
    response = []
    for item in communities:
        communityNames.append((Community.query.filter_by(ID=item.communityID).first()).name)
    for name in communityNames:
        communityPosts.extend(posts.find({ "category": name }))
    for post in communityPosts:
        response.append(post)
    generalPosts.append(posts.find({ "category": "general" }))
    for item in generalPosts:
        for doc in item:
            response.append(doc)
    response.sort(key=lambda r: r['posted_date'], reverse=True)
    for post in response:
        post['posted_date'] = str(post['posted_date']).split(".")[-2]
        post['_id'] = str(post['_id'])
    return response

#api to get the statistics
@app.route('/get_stats', methods = ['GET'])
def getStats():
    communities = len(Community.query.all())
    users = len(User.query.all())
    post = mongo.posts
    posts = post.find()
    count = 0
    for item in posts:
        for doc in item:
            count = count + 1
    response = {
    "users" : users,
    "communities" : communities,
    "posts" : count
    }
    return json.dumps(response)

#api to get the user messages
@app.route('/get_user_messages', methods = ['GET'])
@login_required
def getMessageByUser():
    userID = current_user.username
    messages = mongo.messages
    inbox = []
    sent = []
    inbox.extend(messages.find({ "toUserId": userID }))
    sent.extend(messages.find({"fromUserId": userID}))
    inbox.sort(key=lambda r: r['message_date'], reverse=True)
    sent.sort(key=lambda r: r['message_date'], reverse=True)
    for message in inbox:
        message['message_date'] = str(message['message_date'])
        message['_id'] = str(message['_id'])
    for message in sent:
        message['message_date'] = str(message['message_date'])
        message['_id'] = str(message['_id'])
    response = {
    "inbox": inbox,
    "sent": sent
    }
    return json.dumps(response)

@app.route('/community/<community_id>', methods=['GET', 'POST'])
def community(community_id):
    # print(community_id)
    communityObj = Community.query.filter_by(ID=community_id).first()
    # print (communityObj.name)
    posts = mongo.posts
    communityPosts = posts.find({ "category": communityObj.name })
    # print (communityPosts)
    users = []
    userObj = UserCommunity.query.filter_by(communityID = community_id).all()
    for obj in userObj:
        users.append(obj.userID)
    postFinal = []
    for post in communityPosts:
        postFinal.append(post)
    postFinal.sort(key=lambda r: r['posted_date'], reverse=True)
    for post in postFinal:
        post['posted_date'] = str(post['posted_date'])
        post['_id'] = str(post['_id'])
    moderator = UserModerator.query.filter_by(communityID=community_id).first().moderator
    response = {
    "communityObj" : communityObj,
    "posts" : postFinal,
    "moderator" : moderator,
    "creation_date" : str(communityObj.creation_date).split(" ")[0],
    "users" : users
    }
    print response['users']
    return render_template('community.html',communityObj = response['communityObj'],posts = response['posts'], moderator = response['moderator'],
    date = response['creation_date'], members = response['users'])

#api to get user friends
@app.route('/get_user_friends', methods=['GET'])
def getUserFriends():
    userID = current_user.username
    userCommunity = UserCommunity.query.filter_by(userID = userID).all()
    friends = set()
    for item in userCommunity:
        l = UserCommunity.query.filter_by(communityID = item.communityID).all()
        for user in l:
            friends.add(user.userID)
    current = {userID}
    friendList = friends - current
    response = []
    obj = User.query.filter(User.username.in_(friendList))
    for item in obj:
        data = {
        "username" : item.username,
        "firstName" : item.firstName,
        "lastName" : item.lastName
        }
        response.append(data)
    return json.dumps(response)

# def getListOfCommunities():
#     communities = Community.query.all()
#     communities_name = [community.name for community in communities]
#     return [(k,v) for k,v in enumerate(communities_name)]
#
# def getCommunityId(communityName):
#     communityObj = Community.query.filter_by(name = communityName).first()
#     return communityObj.ID

if __name__ == '__main__':
    app.run(debug = True,threaded=True)
