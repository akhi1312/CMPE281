from index import db
from passlib.apps import custom_app_context as pwd_context
from flask_login import UserMixin

class Community(db.Model):
    __tablename__ = 'community'
    ID = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), index=True, unique=True)
    description = db.Column(db.String(256), index=True)
    address = db.Column(db.String(128), index=True, unique=False)
    city = db.Column(db.String(15), index=True, unique=False)
    zip_code = db.Column(db.Integer, index=True, unique=False)
    creation_date = db.Column(db.DateTime, index=True, unique=False, default=False)
    created_by = db.Column(db.String(128), db.ForeignKey('users.username'))
    status = db.Column(db.String(60), index=True, default="requested")

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    username = db.Column(db.String(128), primary_key=True)
    firstName = db.Column(db.String(128), index=True, unique=False)
    lastName = db.Column(db.String(128), index=True, unique=False)
    email = db.Column(db.String(128), index=True, unique=True)
    password = db.Column(db.String(256), index=True, unique=False)
    contact_number = db.Column(db.String(10), index=True, unique=False)

    def hash_password(self, password):
        self.password = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password)

    def get_id(self):
        return unicode(self.username)

class UserModerator(db.Model):
    __tablename__ = 'user_moderator'
    communityID = db.Column(db.Integer, db.ForeignKey('community.ID'), primary_key=True)
    moderator = db.Column(db.String(128), db.ForeignKey('users.username'), unique=True)

class UserCommunity(db.Model):
    __tablename__ = 'user_community'
    userID = db.Column(db.String(128), db.ForeignKey('users.username'), primary_key=True)
    communityID = db.Column(db.Integer, db.ForeignKey('community.ID'), primary_key=True)

class Admin(db.Model):
    __tablename__ = 'admin'
    admin = db.Column(db.String(128), db.ForeignKey('users.username'), primary_key=True)
