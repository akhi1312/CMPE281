from flask import Flask, render_template, request, make_response, url_for, flash, redirect, session, abort, jsonify,g
import json
import psycopg2
import sys
import pprint
from passlib.apps import custom_app_context as pwd_context

app = Flask(__name__)

#Enter the values for you database connection
dsn_database = "socialCommunity"
dsn_hostname =  "social-community.cznwlohjgx0g.us-west-2.rds.amazonaws.com"
dsn_uid = "myawsuser"
dsn_pwd = "myawsuser"      

try:
    conn_string = "host="+dsn_hostname+" port="+dsn_port+" dbname="+dsn_database+" user="+dsn_uid+" password="+dsn_pwd
    print "Connecting\n"
    conn=psycopg2.connect(conn_string)
    print "Connected!\n"
except:
    print "Unable to connect to the database."

@app.route('/new_community', methods = ['POST'])
def new_community():
    cursor = conn.cursor()
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

@app.route('/sign_up', methods = ['POST'])
def new_user():
    cursor = conn.cursor()
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

if __name__ == '__main__':
    app.run(debug = True,threaded=True)
