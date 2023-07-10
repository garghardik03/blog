from flask import Flask, render_template, request, url_for, flash, redirect, jsonify, session, g, Response
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from backend import (check_auth_login, register_auth_user, verify_usr_eml, string_hash)
import os
import secrets
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
import pymongo


MONGO_HOST_URL = 'mongodb://localhost:27017/'
MONGO_DATABASE_NAME = 'Blog'

MAIL_SERVER='smtp@gmail.com' 
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME='dmyhuev376@iemail.one' #it is the email id from which you want to send the mail
MAIL_PASSWORD='hardik. 203' # it is the password of the email id from which you want to send the mail


salt = 'owui4ht3uhtl2thloKSFB'

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/Blog'
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SECURITY_PASSWORD_SALT'] = salt
app.config['MAIL_SERVER'] = MAIL_SERVER
app.config['MAIL_PORT'] = MAIL_PORT
app.config['MAIL_USE_TLS'] = MAIL_USE_TLS
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
mail = Mail(app)


@app.before_request
def before_request():
    g.user = None
    if 'user' in session:
        g.user = session['user']


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.route('/login', methods=['GET', 'POST'])
def login():
    remember = request.form.get('remember')
    if g.user:  # if user is already logged in
        return render_template('home.html')
    else:
        if request.method == 'GET':
            return render_template('login.html')
        elif request.method == 'POST':
            if check_auth_login(request.form['usr_eml'], request.form['usr_pwd']):
                # it will store the email of the user in the session
                session['user'] = request.form['usr_eml']
                # it will store the email of the user in the global variable
                g.user = session['user']
                if remember:
                    session.permanent = True
                else:
                    session.permanent = False
                flash("Logged in Successfully", "success")
                return redirect(url_for('index'))
                # return render_template('home.html') # it will redirect to home page if login is successful
            else:
                flash("Invalid Credentials", "danger")
                # it will redirect to login page if login is unsuccessful
                return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if g.user:
        return render_template('home.html')
    if request.method == 'GET':
        return render_template('register.html')
    elif request.method == 'POST':
        if register_auth_user(usr_eml=request.form['usr_eml'], usr_fname=request.form['usr_fname'],
                              usr_lname=request.form['usr_lname'], usr_pwd=request.form['usr_pwd'],
                              usr_phone=request.form['usr_phone']):
            flash("Registered Successfullly", "success")
            return render_template('login.html')
        else:
            flash("Registration Failed", "danger")
            return render_template('register.html')


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if g.user:
        g.user = None
        session.pop('user')
        return render_template('login.html')
    else:
        return render_template('login.html')


@app.route('/verify/<string:key>', methods=['GET'])
def verify(key):
    resp = verify_usr_eml(key)
    return Response(f'<script type="text/javascript"> alert("{resp}") </script>')


@app.route('/')
def index():
    posts = mongo.db.Posts.find()
    post = [post for post in posts]
    return render_template('home.html', posts=post)


@app.route("/about")
def about():
    return render_template('about.html')


@app.route("/account", methods=['GET', 'POST'])
def account():
    if g.user:
        # check if the updated data is different from the current one or not
        # it fetches the user from the database with details as a dictionary
        user = mongo.db.auth_user.find_one({"usr_eml": g.user})
        if user is None:
            flash("User not found", "danger")
            return render_template('login.html')
        if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            if username == user['usr_fname'] or email == user['usr_eml']:
                mongo.db.auth_user.update_one(
                    {"usr_eml": g.user}, {"$set": {"usr_fname": username, "usr_eml": email}})
                flash("Your account has been updated", "success")
                return redirect(url_for('account'))
            else:
                flash("No changes made", "info")
        return render_template('account.html', title="Account", user=user)
    else:
        flash("Please login first", "danger")
        return render_template('login.html')



def generate_reset_token(user):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return s.dumps(user['usr_eml'], salt=app.config['SECURITY_PASSWORD_SALT'])


def verify_reset_token(token):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = s.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
        return email
    except:
        return None


def send_password_reset_email(user):
    token = generate_reset_token(user)
    reset_link = request.host_url + f'reset_password/{token}'
    msg = Message(
        subject='Password Reset',
        sender=app.config['MAIL_USERNAME'],
        recipients=[user['usr_eml']],
        body=f"Hello {user['usr_fname']},\n\nYou have requested to reset your password. Please click the link below to reset your password:\n\n{reset_link}\n\nIf you didn't request this, please ignore this email.",
    )
    mail.send(msg)


def generate_password_hash(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')


def check_password_hash(password_hash, password):
    return bcrypt.check_password_hash(password_hash, password)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        user = mongo.db.auth_user.find_one({"usr_eml": email})
        if user:
            send_password_reset_email(user)
            flash('Check your email for the instructions to reset your password', 'info')
        else:
            flash('Email not found', 'warning')
        return redirect(url_for('login'))
    return render_template('reset_password.html')


if __name__ == '__main__':
    app.run(debug=True, port=8000)
