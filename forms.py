from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,BooleanField
from wtforms.validators import DataRequired,Length,Email,EqualTo,ValidationError
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask import Flask, render_template, request,url_for,flash,redirect

app = Flask(__name__)
app.config['MONGO_URI']='mongodb://localhost:27017/Blog'
mongo=PyMongo(app)
app.config['SECRET_KEY']='5791628bb0b13ce0c676dfde280ba245'




class RegistrationForm(FlaskForm):
    username=StringField('Username',validators=[DataRequired(),Length(min=2,max=20)])
    email=StringField('Email',validators=[DataRequired(),Email()])
    password=PasswordField('Password',validators=[DataRequired(),Length(min=8,max=20)])
    confirm_password=PasswordField('Confirm Password',validators=[DataRequired(),EqualTo('password')])
    submit=SubmitField('Sign Up')
    user_data=mongo.db.Users.find()
    user_datas=[user for user in user_data]       
    #self means the username which is being currently passes and other arguement is the username which is being passed from the database
    # def get_usernames(self):
    #     userdatas=mongo.db.Users.find()
    #     usernames=[user['username'] for user in userdatas]
    #     return usernames
    # def validate_username(self,field):
    #     if field.data in self.get_usernames():
    #         raise ValidationError('That username is taken.Please choose a different one.') 
    # def get_emails(self):
    #     user_datas=mongo.db.Users.find()
    #     emails=[user['email'] for user in user_datas]
    #     return emails
    # def validate_email(self,field):
    #     if field.data in self.get_emails():
    #         raise ValidationError('That email is taken.Please choose a different one.')

class LoginForm(FlaskForm):
    email=StringField('Email',validators=[DataRequired(),Email()])
    password=PasswordField('Password',validators=[DataRequired(),Length(min=8,max=20)])
    remember=BooleanField('Remember Me')
    submit=SubmitField('Login')
