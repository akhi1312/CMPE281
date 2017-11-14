from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField, IntegerField, SelectField, ValidationError
from wtforms.validators import InputRequired, Email, Length, NumberRange, EqualTo


class LoginForm(Form):
    """User Login Form"""
    username = StringField('username',validators=[InputRequired(),Length(min=4,max=15)])
    password = PasswordField('password',validators=[InputRequired(),Length(min=8, max=80)])

class RegistrationForm(Form):
    """User Registration Form"""
    communityName = [('1','101'),('2','33south')]
    email = StringField('Email:',validators=[InputRequired(),Email(message='Invalid email'),Length(max=50)])
    username = StringField('Username:', validators=[InputRequired(), Length(min=4, max=15)])
    firstname = StringField('Firstname:', validators=[InputRequired(), Length(min=4, max=30)])
    lastname = StringField('Lastname:', validators=[InputRequired(), Length(min=4, max=30)])
    contact = IntegerField('Contact:', validators=[InputRequired(), NumberRange(min=10,max=10)])
    community = SelectField('Residential community:',choices = communityName,validators=[InputRequired()])
    password = PasswordField('Password:',validators=[InputRequired(),Length(min=8, max=80), EqualTo('confirm_password')])
    confirm_password = PasswordField('Confirm Password:')

    # def validateEmail(self,_email):
    #     if User.query.filter_by(email=_email).first():
    #         raise ValidationError('Email is already in use.')
    #
    # def validateUserName(self,_username):
    #     if User.query.filter_by(username=_username).first():
    #         raise ValidationError('Username is already in use.')

class CommunityForm(Form):
    """New Community Registration Form"""
    communityName = [('1', '101'), ('2', '33south')]
    email = StringField('Email:', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('Username:', validators=[InputRequired(), Length(min=4, max=15)])
    firstname = StringField('Firstname:', validators=[InputRequired(), Length(min=4, max=30)])
    lastname = StringField('Lastname:', validators=[InputRequired(), Length(min=4, max=30)])
    contact = IntegerField('Contact:', validators=[InputRequired(), NumberRange(min=10, max=10)])
    community = SelectField('Residential community:', choices=communityName, validators=[InputRequired()])
    password = PasswordField('Password:',
                             validators=[InputRequired(), Length(min=8, max=80), EqualTo('confirm_password')])
    confirm_password = PasswordField('Confirm Password:')
