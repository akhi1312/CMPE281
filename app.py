from flask import Flask, render_template, request, make_response, url_for, flash, redirect, session, abort, jsonify, g, current_app
from flask_moment import Moment
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from Forms import LoginForm, RegistrationForm, commuityRegistraion, ArticleForm , EditForm, EditArticleForm, CommentForm, ChatForm
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
from models import Community, User, UserCommunity, UserModerator, UserRequestedCommunity
import  myexception
from flask_httpauth import HTTPBasicAuth
from awsServices import send_email, sendMessage
from flask_mail import Mail,Message
from threading import Thread
from flask_pagedown import PageDown

from bson.objectid import ObjectId

from markdown import markdown
import bleach

auth = HTTPBasicAuth()
import pprint

pagedown = PageDown()
app = Flask(__name__)
moment = Moment(app)
Bootstrap(app)
app.config['SECRET_KEY'] = os.urandom(32)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_message = "You should be logged in to view this page"
login_manager.login_view = 'login'

# Flask Mail settings
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'socialnetwork281@gmail.com'
app.config['MAIL_PASSWORD'] = 'Cmpe@281'
app.config['MAIL_DEBUG'] = True

app.config['FLASKY_MAIL_SUBJECT_PREFIX'] = '[SocialNetwork]'
app.config['FLASKY_MAIL_SENDER'] = 'Admin <socialnetwork281@gmail.com>'
app.config['SOCIALNETWORK_ADMIN'] = 'socialnetwork281@gmail.com'
pagedown.init_app(app)
mail = Mail(app)


listOfAuthAPIs = ['login','unconfirmed','logout','sign_up','confirm','resend_confirmation']

allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'p']
def convertIntoHTML(value):
    return bleach.linkify(bleach.clean(markdown(value, output_format='html'),tags=allowed_tags, strip=True))

def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_email(to, subject, template, **kwargs):
    msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject,
                  sender=app.config['FLASKY_MAIL_SENDER'], recipients=[to])
    # msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    thr = Thread(target=send_async_email, args=[app, msg])
    thr.start()
    return thr
# Flask Mail settings

#Confirmation Email
@app.route('/confirm/<token>')
@login_required
def confirm(token):
    print token
    if current_user.status == 'approved':
        return redirect(url_for('home'))
    if current_user.confirm(token):
        db.session.commit()
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('home'))

@app.before_request
def before_request():
    print request.endpoint
    if current_user.is_authenticated \
            and current_user.status != 'approved'\
            and request.endpoint not in listOfAuthAPIs \
            and request.endpoint != 'static':
        return redirect(url_for('unconfirmed'))

@app.route('/unconfirmed')
def unconfirmed():
    print current_user.status
    if current_user.status == 'approved' or current_user.is_anonymous:
        return redirect(url_for('home'))
    return render_template('_unconfirmed.html')

@app.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
               '_confirmemail', user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('home'))

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
    adminData = getStats()
    listOfRequestedCommunitites = getRequestedCommunity()
    return render_template('admin.html', adminData=adminData , listOfRequestedCommunitites=listOfRequestedCommunitites)

@app.route('/admin_users', methods = ['GET','POST'])
def admin_users():
    adminData = getStats()
    users = User.query.order_by((User.joining_date)).all()
    return render_template('admin_users.html',users=users , adminData=adminData )

@app.route('/admin_community', methods = ['GET','POST'])
def admin_community():
   adminData = getStats()
   # categories = getUserCommunities()
   communityDetails = adminCommunityData()
   return render_template('admin_community.html',communityDetails=communityDetails, adminData=adminData )

@app.route('/admin_post', methods = ['GET','POST'])
def admin_post():
    adminData = getStats()
    listOfPost = mongo.posts.find({})
   
    return render_template('admin_post.html',adminData=adminData,listOfPost=listOfPost)


#edit community 
@app.route('/admin/edit_community/<community_id>', methods = ['GET','POST'])
def edit_community(community_id):
    communityID = int(community_id)
    print "Printing Comuity"
    communityDetails = Community.query.filter_by(ID=communityID).first()
    form = commuityRegistraion()
    if form.validate_on_submit():
        communityDetails.name = form.name.data.lower()
        communityDetails.desc = form.desc.data
        communityDetails.address = form.address.data
        communityDetails.city = form.city.data
        communityDetails.zip_code = form.zip_code.data
        db.session.commit()
        return redirect(url_for('admin_community'))
    else:
        communityDetails = Community.query.filter_by(ID=communityID).first()
        form.name.data = communityDetails.name
        form.desc.data = communityDetails.description
        form.address.data = communityDetails.address
        form.city.data = communityDetails.city
        form.zip_code.data = communityDetails.zip_code
        # form.creation_date.data = communityDetails.creation_date
        # form.created_by.data = communityDetails.created_by
        return render_template('_edit_community.html',form=form ,column = communityID)


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
            return render_template('_newCommunity.html',form=form)
        db.session.add(com)
        db.session.commit()
        message = 'Hi Admin, This is to inform that '+current_user.username+' has created a new commmunity named as '+name+'. User email is '+ current_user.email +' . Please Approve it.'
        subject = 'New Community '+ name + ' acceptance mail.'
        # send_email(message, subject)
        # sendMessage(current_user.contact_number,current_user.username, name)
        flash('Community ' + name + ' has been created. Waiting for admin approval.' )
        return redirect(url_for('home'))
    return render_template('_newCommunity.html',form=form)

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
            return render_template('_signup.html', form=form)
        elif User.query.filter_by(email=email).first() is not None:
            flash("Email already registered")
            form = RegistrationForm()
            return render_template('_signup.html', form=form)
        db.session.add(new_user)
        db.session.commit()
        if app.config['SOCIALNETWORK_ADMIN']:
            send_email(app.config['SOCIALNETWORK_ADMIN'], ' New User',
                       '_newuser', user=new_user)
            token = new_user.generate_confirmation_token()
            send_email(new_user.email, 'Confirm Your Account',
                       '_confirmemail', user=new_user, token=token)
            flash('A confirmation email has been sent to you by email.')
        flash('Registration has been done successfully. Please login.')
        return redirect(url_for('login'))
    return render_template('_signup.html', form=form)

#add new post
@app.route('/add_post', methods = ['POST'])
def add_post(category,title,content,content_html):
    posts = mongo.posts
    impagePath = None
    if not current_user.imageUrl:
        impagePath = current_user.gravatar()
    else:
        impagePath = current_user.imageUrl
    post_data = {
        'category':category.lower(),
        'title': title,
        'content': content,
        'contentHTML': content_html,
        'author': current_user.username,
        'authorImage': impagePath,
        'posted_date': datetime.datetime.utcnow(),
        'comments': []
    }
    result = posts.insert_one(post_data)
    print 'One post: {0}'.format(result.inserted_id)

@app.route('/messages',methods=['GET'])
def messages():
    friends = getUserFriends()
    for friend in friends:
        print friend
    return render_template('messages.html', members = friends, selectedUser = None)

@app.route('/messages/<username>',methods=['GET', 'POST'])
def retrieveMessagesOfUser(username):
    print username
    form = ChatForm()
    if form.validate_on_submit():
        print form.msg.data
        msg = form.msg.data
        add_message(username,msg)
        form.msg.data = ''
    friends = getUserFriends()
    convos = get_messages(current_user.username,username)
    for friend in friends:
        print friend
    return render_template('messages.html', members=friends, form = form, selectedUser = username, conversations = convos )

@app.route('/sendmessages', methods=['POST'])
def saveMessage():
    print "here"
    msg = request.form['msg']
    print msg
    return render_template('messages.html', message = msg, timestamp = datetime.datetime.utcnow())

@app.route('/joincommunity',methods=['GET'])
def listOfCommunitites():
    joinedCommunities = getCommunityDetailsJoined()
    unjoinedCommunities = getCommunityDetailsUnjoined()
    requestedCommunities = getCommunityDetailsRequested()
    return render_template('_joincommunity.html',joined = joinedCommunities, unjoined = unjoinedCommunities, requested = requestedCommunities)

#add comment to a post
@app.route('/add_post_comment', methods = ['POST'])
def add_post_comment():
    mongo.posts.update_one(
    {"_id": request.json['_id']},
    {"$push": {
        'comments': {
                    'posted': datetime.datetime.now(),
                    'text': request.json['text']
                }
            }
        }
    )
    return ("Comment Added to post " + str(request.json['_id']))

def msg_to_json(recipient, msg):
    message_data = {
        'fromUserId': recipient,
        'msg': msg,
        'toUserId': current_user.username,
        'message_date': datetime.datetime.utcnow()
    }
    return message_data
#add message
# @app.route('/add_message', methods = ['POST'])
def add_message(recipient, msg):
    messages = mongo.messages
    message_data = {
        'fromUserId':current_user.username,
        'msg': msg,
        'toUserId': recipient,
        'message_date': datetime.datetime.utcnow()
    }
    result = messages.insert_one(message_data)
    print 'One message: {0}'.format(result.inserted_id)

def get_messages(person1, person2):
    listOfConversations = []
    messages = mongo.messages.find({'fromUserId':person1, 'toUserId':person2})
    for message in messages:
        listOfConversations.append(message)
    replies = mongo.messages.find({'fromUserId': person2, 'toUserId': person1})
    for reply in replies:
        listOfConversations.append(reply)
    listOfConversations.sort(key=lambda r: r['message_date'], reverse=True)
    return listOfConversations

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
    form = ArticleForm(categories, category=0)
    display_posts = getPostsByUser()
    communities = getUserCommunities()
    if form.validate_on_submit():
        print 'inside add post'
        title = form.title.data
        # body = form.body.data.split('<p>')[1].split('</p>')[0]
        body = form.body.data
        content_html = convertIntoHTML(body)
        print body
        print form.category.data
        category = dict(categories).get(form.category.data)
        add_post(category,title,body,content_html)
        form.title.data = ""
        form.body.data = ""
        form.category.data = ""
        display_posts = getPostsByUser()
    return render_template('_userdashboard.html',form=form, posts = display_posts, communities = communities)

@app.before_request
def before_request():
    g.user = current_user

@app.route('/profile/<username>', methods=['GET', 'POST'])
@login_required
def profilefrnd(username):
    userposts = mongo.posts.find({ "author": username })
    userFriends = getUserFriends(username)
    user = User.query.filter_by(username=username).first()
    form = EditForm(request.form)
    return render_template('profile.html', user = user , userposts = userposts , userFriends = userFriends,form=form)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    username = session['username']
    userposts = mongo.posts.find({ "author": username })
    userFriends = getUserFriends()
    user = User.query.filter_by(username=username).first()
    for friends in userFriends:
        print friends

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
    return render_template('profile.html', form=form , userposts = userposts , userFriends = userFriends ,user = user)

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
                flash('You have successfully logged In')
                print user.status
                print current_user.status
                return redirect(url_for('home'))
            else:
                flash('password is incorrect')
        else:
            flash('User is not registered')
    return render_template('_login.html',form=form)

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
        communityList.append(item)
    return communityList

#api to approve a requested community
@app.route('/approve_community/<communityId>', methods = ['GET'])
def approveCommunity(communityId):
    # communityName = request.json['name'].lower()
    # communityDetails = Community.query.filter_by(name = communityName).first()
    communityDetails = Community.query.filter_by(ID=communityId).first()
    created_by = communityDetails.created_by
    user_comm = UserCommunity(userID=created_by,
                        communityID=communityId)
    user_mod = UserModerator(communityID=communityId,
    moderator=created_by)
    communityDetails.status = 'Approved'
    db.session.add(user_comm)
    db.session.add(user_mod)
    db.session.commit()
    return redirect(url_for('admin'))

#api to join a community
@app.route('/join_community', methods = ['POST'])
def joinCommunity():
    userID = request.form['username']
    communityID = request.form['id']
    print userID
    print communityID
    user_comm = UserCommunity(userID=userID,
                        communityID=communityID)
    UserRequestedCommunity.query.filter_by(communityID=communityID, userID=userID).delete()
    db.session.add(user_comm)
    db.session.commit()
    communityName = (Community.query.filter_by(ID=communityID).first()).name
    message = 'Hi Moderator, This is to inform that '+current_user.username+' has joined '+communityName+' community. User email is '+ current_user.email +' .'
    subject = 'New Member Joined to '+ communityName + ' community.'
    data = {
        'status':200
    }
    return json.dumps(data)




# Delete Communit modified Akhilesh

@app.route('/delete_community', methods = ['POST'])
def deleteCommunity():
    communityID = request.form['id']
    deleteCommunity(communityID)
    data = {
            'status':200
        }
    return json.dumps(data)

@app.route('/delete_post', methods = ['POST'])
def deletePost():
    postId = request.form['id']
    print postId
    mongo.posts.remove( {"_id" : ObjectId(str(postId)) } )
    data = {
            'status':200
        }
    return json.dumps(data)

@app.route('/delete_user', methods = ['POST'])
def deleteUser():
    userName = request.form['id']

    deleteUser(userName)
    data = {
            'status':200
        }
    return json.dumps(data)




# Code End
@app.route('/join_request', methods = ['POST'])
def joiningRequest():
    userID = current_user.username
    communityID = request.form['id']
    user_comm = UserRequestedCommunity(userID=userID,
                        communityID=communityID)
    db.session.add(user_comm)
    db.session.commit()
    communityName = (Community.query.filter_by(ID=communityID).first()).name
    message = 'Hi Moderator, This is to inform that '+current_user.username+' has requested to joined '+communityName+ "community."
    subject = 'New Member Requested to Join '+ communityName + ' community.'
    data = {
        'status':200
    }
    return json.dumps(data)

@app.route('/decline_request_user', methods = ['POST'])
def declineRequestByUser():
    userID = current_user.username
    communityID = request.form['id']
    UserRequestedCommunity.query.filter_by(communityID=communityID, userID=userID).delete()
    db.session.commit()
    data = {
        'status':200
    }
    return json.dumps(data)

#api route to
@app.route('/reject_request', methods = ['POST'])
def rejectRequestModerator(communityId):
    userID = request.form['username']
    communityID = request.form['id']
    print userID
    print communityID
    UserRequestedCommunity.query.filter_by(communityID=communityID, userID=userID).delete()
    db.session.commit()
    data = {
        'status': 200
    }
    return json.dumps(data)

#api to join a community
@app.route('/leave_community', methods = ['POST'])
def leaveCommunity():
    userID = current_user.username
    communityID = request.form['id']
    obj = UserModerator.query.filter_by(communityID=communityID).first().moderator
    if obj == userID:
        flash("User cannot be removed", "alert")
        data = {
            'status':200
        }
        return json.dumps(data)
    else:
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
    return response

#api to get full community details for a unjoined user community
@app.route('/user_unjoined_community', methods = ['GET'])
def getCommunityDetailsUnjoined():
    communities = UserCommunity.query.filter_by(userID=current_user.username).all()
    totalCommunities = Community.query.filter_by(status = 'Approved').all()
    requestedCommunities = UserRequestedCommunity.query.filter_by(userID=current_user.username).all()
    jid = set()
    tid = set()
    rid = set()
    for community in requestedCommunities:
        rid.add(community.communityID)
    for community in communities:
        jid.add(community.communityID)
    for community in totalCommunities:
        tid.add(community.ID)
    unjoined_temp =  tid - jid
    unjoined = unjoined_temp - rid
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
    return response

#api to get full community details for a unjoined user community
@app.route('/user_requested_community', methods = ['GET'])
def getCommunityDetailsRequested():
    requestedCommunities = UserRequestedCommunity.query.filter_by(userID=current_user.username).all()
    rid = set()
    for community in requestedCommunities:
        rid.add(community.communityID)

    moderators = []
    response = []
    communityObj = []
    users = []
    for id in rid:
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
    return response

#method to delete a community
def deleteCommunity(communityID):
    UserCommunity.query.filter_by(communityID = communityID).delete()
    UserModerator.query.filter_by(communityID=communityID).delete()
    communityObj = Community.query.filter_by(ID=communityID).first()
    name = communityObj.name
    posts = mongo.posts
    mongo.get_collection('posts').delete_many({"category": name})
    Community.query.filter_by(ID=communityID).delete()
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
        post['_id'] = str(post['_id'])
        print post['authorImage']
    return response

#api to get the statistics
#@app.route('/get_stats', methods = ['GET'])
def getStats():
    communities = len(Community.query.all())
    users = len(User.query.all())
    post = mongo.posts
    posts = post.find()
    count = 0
    for item in posts:
        count = count + 1
    response = {
    "users" : users,
    "communities" : communities,
    "posts" : count
    }
    return response

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
    communityObj = Community.query.filter_by(ID=community_id).first()
    posts = mongo.posts
    communityPosts = posts.find({ "category": communityObj.name })
    users = []
    userObj = UserCommunity.query.filter_by(communityID = community_id).all()
    for obj in userObj:
        users.append(obj.userID)
    postFinal = []
    for post in communityPosts:
        postFinal.append(post)
    postFinal.sort(key=lambda r: r['posted_date'], reverse=True)
    for post in postFinal:
        post['_id'] = str(post['_id'])
    moderator = UserModerator.query.filter_by(communityID=community_id).first().moderator
    response = {
    "communityObj" : communityObj,
    "posts" : postFinal,
    "moderator" : moderator,
    "creation_date" : communityObj.creation_date,
    "users" : users
    }
    print response['users']
    return render_template('_community.html',communityObj = response['communityObj'],posts = response['posts'], moderator = response['moderator'],
    date = response['creation_date'], members = response['users'])

#api to get user friends
@app.route('/get_user_friends', methods=['GET'])
def getUserFriends(username = None):
    if  not username:
        userID = current_user.username
    else:
        userID = username
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
    # for item in obj:
    #     data = {
    #     "username" : item.username,
    #     "firstName" : item.firstName,
    #     "lastName" : item.lastName
    #     }
    #     response.append(data)
    # return response
    return obj

# Below Commented by Akhilesh - Didnot understand the functnality

#@app.route('/delete_user', methods = ['POST'])
def deleteUser(userID):
    #userID = request.json['userID']
    moderator = UserModerator.query.filter_by(moderator=userID).all()
    if len(moderator) != 0:
        flash("Delete user from moderator list")
    else:
        UserCommunity.query.filter_by(userID=userID).delete()
        User.query.filter_by(username=userID).delete()
        db.session.commit()


@app.route('/requestedCommunities')
def adminToApprove():
    listOfRequestedCommunitites = getRequestedCommunity()
    for item in listOfRequestedCommunitites:
        print item
    return render_template('_requestedCommunity.html', requestedCommunities = listOfRequestedCommunitites)

@app.route('/post/<id>', methods=['GET','POST'])
def post(id):
    form = CommentForm()
    if form.validate_on_submit():
        if form.comment.data:
            impagePath = None
            if not current_user.imageUrl:
                impagePath = current_user.gravatar()
            else:
                impagePath = current_user.imageUrl
            mongo.posts.update_one(
            {"_id": ObjectId(str(id))},
            {"$push": {
                'comments': {
                    'author': { 'name': current_user.username, 'imageUrl' : impagePath},
                    'posted': datetime.datetime.utcnow(),
                    'text': form.comment.data,
                    'disabled': False
                        }
                    }
                }
            )
            form.comment.data = ''
            flash('Your comment has been added')
    _id = str(id)
    post = mongo.posts.find_one({ "_id": ObjectId(_id) })
    return render_template('_post.html', post=post, commentForm=form)


@app.route('/editpost/<id>', methods=['GET', 'POST'])
@login_required
def editPost(id):
    _id = str(id)
    post = mongo.posts.find_one({ "_id": ObjectId(_id) })
    categories = getUserCommunities()
    categories.append((0,'General'))
    name = post['category']
    category = Community.query.filter_by(name=name).first()
    if category:
        categoryId = category.ID
    else:
        categoryId = 0
    form = EditArticleForm(categories,category=categoryId)
    if form.validate_on_submit():
        title = form.title.data
        body = form.body.data
        content_html = convertIntoHTML(body)
        category = dict(categories).get(form.category.data)
        print body
        post['title'] = title
        post['conntent'] = body
        post['contentHTML'] = content_html
        post['category'] = category
        flash('The post has been updated.')
        # Below route need to be changed..
        mongo.posts.update_one({
              '_id': post['_id']
            },{
              '$set': {
                'title': title,
                'content': body,
                'contentHTML': content_html,
                'category':category,
                'posted_date':datetime.datetime.utcnow()
              }
            }, upsert=False)
        flash('Your post has been updated')
        return redirect(url_for('home'))
    form.title.data = post['title']
    form.body.data = post['content']
    return render_template('_editPost.html', form=form, id = id)

# def admin():
#     userModObj = UserModerator.query.all()
#     communityNames = []
#     for obj in userModObj:


def adminCommunityData():
    userMod = UserModerator.query.all()
    response = []
    for obj in userMod:
        username = obj.moderator
        communityID = obj.communityID
        userObj = User.query.filter_by(username = username).first()
        firstName = userObj.firstName
        lastName = userObj.lastName
        communityObj = Community.query.filter_by(ID = communityID).first()
        communityName = communityObj.name
        creation_date = communityObj.creation_date
        data = {
        "username" : username,
        "communityID" : communityID,
        "firstName" : firstName,
        "lastName" : lastName,
        "communityName" : communityName,
        "creation_date" : creation_date
        }
        response.append(data)
    return response

@app.route('/requestedtojoincommunitites', methods=['GET'])
def moderatorUserData():
    current_moderator = current_user.username
    print current_moderator
    moderatorCommObj = UserModerator.query.filter_by(moderator=current_moderator).all()
    communityName = []
    moderator_communities = []
    requested = []
    response = []
    for obj in moderatorCommObj:
        moderator_communities.append(obj.communityID)
    for id in moderator_communities:
        name = Community.query.filter_by(ID=id).first().name
        print name
        userReqObj = UserRequestedCommunity.query.filter_by(communityID=id).all()
        if userReqObj is not None:
            for obj in userReqObj:
                user = User.query.filter_by(username=obj.userID).first()
                print user.username
                data = {
                "community_id" : id,
                "community_name" : name,
                "username" : user.username
                }
                response.append(data)
    return render_template('_requestedCommunities.html', response=response)



@app.route('/network', methods=['GET'])
def getNetwork():
    communityObj = Community.query.all()

    userCommunity = UserCommunity.query.all()
    # userCommObj =
    communities = []
    users = []
    for obj in communityObj:
        # cin[obj.ID] = obj.name
        communities.append([obj.ID, obj.name])
    # print (response)
    start = 999
    for obj in userCommunity:
        data = {
        "id" : start,
        "name" : obj.userID,
        "com" : obj.communityID
        }
        users.append(data)
        start = start - 1

    response = {
    "community" : communities,
    "user" : users
    }

    return json.dumps(response)

@app.route('/graph', methods=['GET'])
def render_graph():
    return render_template("test.html")

if __name__ == '__main__':
    app.run(debug = True,threaded=True)
