from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField, IntegerField, SelectField, ValidationError, TextAreaField
from wtforms.validators import InputRequired, Email, Length, NumberRange


class LoginForm(Form):
    """User Login Form"""
    username = StringField('username',validators=[InputRequired(),Length(min=4,max=15)])
    password = PasswordField('password',validators=[InputRequired(),Length(min=8, max=80)])
    rememberMe = BooleanField('Remember Me',default=False)

class RegistrationForm(Form):
    """User Registration Form"""

    email = StringField('Email:',validators=[InputRequired(),Email(message='Invalid email'),Length(max=50)])
    username = StringField('Username:', validators=[InputRequired(), Length(min=4, max=15)])
    firstname = StringField('Firstname:', validators=[InputRequired(), Length(min=4, max=30)])
    lastname = StringField('Lastname:', validators=[InputRequired(), Length(min=4, max=30)])
    contact = IntegerField('Contact:', validators=[InputRequired()])
    password = PasswordField('Password:',validators=[InputRequired(),Length(min=8, max=80)])

    # def validateEmail(self,_email):
    #     if User.query.filter_by(email=_email).first():
    #         raise ValidationError('Email is already in use.')
    #
    # def validateUserName(self,_username):
    #     if User.query.filter_by(username=_username).first():
    #         raise ValidationError('Username is already in use.')

class commuityRegistraion(Form):
    """User Registration Form"""
    name = StringField('Name:', validators=[InputRequired(), Length(max=50)])
    desc = StringField('Description:',validators=[Length(max=256)])
    address = StringField('Address:', validators=[InputRequired(), Length(min=4, max=50)])
    city = StringField('City:', validators=[InputRequired(), Length(max=30)])
    zip_code = IntegerField('ZipCode:', validators=[InputRequired()])

# Post Form Class
class ArticleForm(Form):
    title = StringField('Title', validators=[InputRequired(),Length(min=1, max=25)])
    body = TextAreaField('Body', validators=[InputRequired(),Length(max=256)])
    language = SelectField(
        'Category',
        choices=[('cpp', 'C++'), ('py', 'Python'), ('text', 'Plain Text')]
    )




