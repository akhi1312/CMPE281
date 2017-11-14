from index import db

class Community(db.Model):
    __tablename__ = 'community'
    ID = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), index=True, unique=True)
    address = db.Column(db.String(128), index=True, unique=False)
    city = db.Column(db.String(15), index=True, unique=False)
    zip_code = db.Column(db.Integer, index=True, unique=False)
    creation_date = db.Column(db.DateTime, index=True, unique=False, default=False)

class User(db.Model):
    __tablename__ = 'users'
    username = db.Column(db.String(128), primary_key=True)
    communityID = db.Column(db.Integer, db.ForeignKey('community.ID'), index=True)
    firstName = db.Column(db.String(128), index=True, unique=False)
    lastName = db.Column(db.String(15), index=True, unique=False)
    email = db.Column(db.String(15), index=True, unique=True)
    password = db.Column(db.String(15), index=True, unique=False)
    contact_number = db.Column(db.String(30), index=True, unique=False)
