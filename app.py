from flask import Flask, render_template, request, make_response, url_for, flash, redirect, session, abort, jsonify,g
import json
import psycopg2
import sys
import pprint
from passlib.apps import custom_app_context as pwd_context
from pymongo import MongoClient
import datetime
import pprint

app = Flask(__name__)

#Enter the values for you database connection
dsn_database = "socialCommunity"
dsn_hostname =  "social-community.cznwlohjgx0g.us-west-2.rds.amazonaws.com"
dsn_uid = "myawsuser"
dsn_pwd = "myawsuser"

#connecting to RDS AWS
try:
    conn_string = "host="+dsn_hostname+" port="+dsn_port+" dbname="+dsn_database+" user="+dsn_uid+" password="+dsn_pwd
    print "Connecting\n"
    conn=psycopg2.connect(conn_string)
    print "Connected!\n"
except:
    print "Unable to connect to the database."

#connection cursor to RDS
cursor = conn.cursor()

#connecting to MongoDB
client = MongoClient("mongodb://admin:admin@ds251845.mlab.com:51845/socialcommunity")
db = client['socialcommunity']

#create new community
@app.route('/new_community', methods = ['POST'])
def new_community():
    ID = request.json['ID']
    name = request.json['name']
    address = request.json['address']
    city = request.json['city']
    zip_code = request.json['zip_code']
    creation_date = request.json['creation_date']
    cursor.execute("INSERT INTO Community VALUES (%s, %s, %s, %s)", (ID, name, address, city, zip_code,\
    creation_date))
    conn.commit()
    return "Community " + u + " added."

#create new user
@app.route('/sign_up', methods = ['POST'])
def new_user():
    username = request.json['username']
    communityID = request.json['communityID']
    firstName = request.json['firstName']
    lastName = request.json['lastName']
    email = request.json['email']
    password = request.json['password']
    contact_number = request.json['contact_number']
    cursor.execute("INSERT INTO Users VALUES (%s, %s, %s, %s, %s, %s, %s)", (username, communityID, firstName,\
    lastName, email, password, contact_number))
    conn.commit()
    return "User " + u + " added."

#add new post
@app.route('/add_post', methods = ['POST'])
def add_post():
    posts = db.posts
    post_data = {
        'title': request.json['title'],
        'content': request.json['content'],
        'author': request.json['author'],
        'attachment': request.json['attachment'],
        'posted_date': datetime.datetime.now(),
    }
    result = posts.insert_one(post_data)

#add comment to a post
@app.route('/add_post_comment', methods = ['POST'])
def add_post_comment():
    db.posts.update_one(
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

#add message
@app.route('/add_message', methods = ['POST'])
def add_message():
    messages = db.messages
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

#add message
@app.route('/add_message', methods = ['POST'])
def add_message():
    messages = db.messages
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

#add complaint
@app.route('/add_complaint', methods = ['POST'])
def add_complaint():
    complaints = db.complaints
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

if __name__ == '__main__':
    app.run(debug = True,threaded=True)
