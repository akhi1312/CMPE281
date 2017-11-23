from index import db
from passlib.apps import custom_app_context as pwd_context
from flask_login import UserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app

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
    city = db.Column(db.String(256), index=True, unique=False)
    contact_number = db.Column(db.String(10), index=True, unique=False)
    joining_date = db.Column(db.DateTime, index=True, unique=False, default=False)
    imageUrl = db.Column(db.String(256), index=True, unique=False)
    aboutMe = db.Column(db.String(512), index=True, unique=False)
    role = db.Column(db.String(60), index=True, unique=False)
    status = db.Column(db.String(60), index=True, default="requested")

    def hash_password(self, password):
        self.password = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password)

    def get_id(self):
        return unicode(self.username)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.username}).decode('utf-8')

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        if data.get('confirm') != self.username:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

class UserModerator(db.Model):
    __tablename__ = 'user_moderator'
    communityID = db.Column(db.Integer, db.ForeignKey('community.ID'), primary_key=True)
    moderator = db.Column(db.String(128), db.ForeignKey('users.username'), primary_key=True)

class UserCommunity(db.Model):
    __tablename__ = 'user_community'
    userID = db.Column(db.String(128), db.ForeignKey('users.username'), primary_key=True)
    communityID = db.Column(db.Integer, db.ForeignKey('community.ID'), primary_key=True)

class Admin(db.Model):
    __tablename__ = 'admin'
    admin = db.Column(db.String(128), db.ForeignKey('users.username'), primary_key=True)
