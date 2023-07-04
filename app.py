from flask import Flask, render_template, request,url_for,flash,redirect
from flask_pymongo import PyMongo
from forms import RegistrationForm,LoginForm
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['MONGO_URI']='mongodb://localhost:27017/Blog'
mongo=PyMongo(app)
app.config['SECRET_KEY']='5791628bb0b13ce0c676dfde280ba245'
bcrypt=Bcrypt(app)

def is_unique(field, value):
    existing_user = mongo.db.Users.find_one({field: value})
    already_user=[user for user in existing_user]
    return already_user


@app.route('/')
def index():
    users=mongo.db.Users.find()
    user=[user for user in users]
    posts=mongo.db.Posts.find()
    post=[post for post in posts]
    return render_template('home.html',posts=post,user=user)

@app.route("/about")
def about():
    return render_template('about.html')

@app.route("/register",methods=['GET','POST'])
def register():
    form=RegistrationForm()
    if form.validate_on_submit():
        if not is_unique('username', form.username.data):
            flash("Username already exists","danger")
            print("Username already exists")
        elif not is_unique('email', form.email.data):
            flash("Email already exists","danger")
            print("Email already exists")
        else:
            hashed_password=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user={'username':form.username.data,'email':form.email.data,'password':hashed_password,'image_file':'default.jpg',"posts":[]}
            mongo.db.User.insert_one(user)
            flash("Your account has been! You are now able to log in","success")
            return redirect(url_for('login'))
    return render_template('register.html',title='Register',form=form)

@app.route("/login",methods=['GET','POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        if form.email.data=='admin@blog.com' and form.password.data=='password':
            flash("You have been logged in!","success")
            return redirect(url_for('index'))
        else:
            flash("Login Unsuccessful. Please check username and password","danger")
    return render_template('login.html',title='Login',form=form)

if __name__ == '__main__':
    app.run(debug=True,port=8000)
