from flask import Flask, render_template, request, url_for, flash, redirect, jsonify, session, g, Response
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from backend import (check_auth_login, register_auth_user, verify_usr_eml, string_hash)
import os
import secrets
import pymongo
import razorpay


razorpay_client = razorpay.Client(auth=('rzp_test_3fT7czS7jEsTzs', 'Ne27btY8oetWfz3rAy7pe6dB'))


MONGO_HOST_URL = 'mongodb://localhost:27017/'
MONGO_DATABASE_NAME = 'Blog'

# MAIL_SERVER='smtp.gmail.com' 
# MAIL_PORT=587
# MAIL_USE_TLS=True
# MAIL_USERNAME='dmyhuev376@iemail.one' #it is the email id from which you want to send the mail
# MAIL_PASSWORD='hardik. 203' # it is the password of the email id from which you want to send the mail


salt = 'owui4ht3uhtl2thloKSFB'

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/Blog'
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SECURITY_PASSWORD_SALT'] = salt
# app.config['MAIL_SERVER'] = MAIL_SERVER
# app.config['MAIL_PORT'] = MAIL_PORT
# app.config['MAIL_USE_TLS'] = MAIL_USE_TLS
# app.config['MAIL_USERNAME'] = MAIL_USERNAME
# app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
mongo = PyMongo(app)
bcrypt = Bcrypt(app)


@app.route('/payment', methods=['POST','GET'])
def payment():
    # Get the payment amount from the request
    amount = request.form.get('amount')
    if amount:
        amount = int(amount) * 100  # Convert to paise
    else:
        # Show an error message
        flash('Amount is required!')
        return redirect(url_for('payment'))

    # Create a Razorpay order
    order = razorpay_client.order.create({'amount': amount, 'currency': 'INR'})

    # Save the order details to MongoDB
    client = pymongo.MongoClient('mongodb://localhost:27017/')
    db = client['Blog'] 
    orders = db['orders']
    orders.insert_one({'order_id': order['id'], 'amount': amount})

    # Render the payment form with the order details
    return render_template('payment.html', order=order)

@app.route('/payment/success', methods=['POST'])
def payment_success():
    # Get the payment response from the request
    response = request.form

    # Verify the payment signature
    signature = response.get('razorpay_signature')
    order_id = response.get('razorpay_order_id')
    payment_id = response.get('razorpay_payment_id')

    # Verify the payment signature using the Razorpay client
    try:
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        })
    except razorpay.errors.SignatureVerificationError:
        return 'Payment verification failed'

    # Update the payment status in MongoDB
    client = pymongo.MongoClient('mongodb://localhost:27017/')
    db = client['Blog']
    orders = db['orders']
    orders.update_one({'order_id': order_id}, {'$set': {'status': 'success'}})

    # Render the payment success page
    return render_template('payment_success.html')




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
                              usr_phone=request.form['usr_phone'],sec_question=request.form['sec_question'], sec_answer=request.form['sec_answer']):
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



def generate_password_hash(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')


def check_password_hash(password_hash, password):
    return bcrypt.check_password_hash(password_hash, password)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        sec_question = request.form['sec_question']
        sec_answer = request.form['sec_answer']
        
        # Find user by email 
        user = mongo.db.auth_user.find_one({'usr_eml': email})
        
        if user is not None:
            # Validate security question and answer
            if user['sec_question'] == sec_question and user['sec_answer'] == sec_answer:
                # Hash the new password
                hashed_password = generate_password_hash(password)
            
                # Update user password
                mongo.db.auth_user.update_one({'usr_eml': email}, {'$set': {'usr_pwd': hashed_password}})
            
                flash('Password updated!', 'success')
                return redirect(url_for('login'))
            else:
                flash('Security answer is incorrect.', 'danger')
                return redirect(url_for('reset_password'))
        else:
            flash('No user found with that email address.', 'danger')
            return redirect(url_for('reset_password'))
            
    return render_template('reset_password.html')


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    #the details filled by the user in the contact form will be stored in the database in the collection contact
    if request.method == 'POST':
        #create a collection contact in the database
        contact = mongo.db.contact
        #insert the details in the database
        # the message is not inserted as a whole in the databse so write a code such that whole message is inserted in the database
        mongo.db.contact.insert_one({'name': request.form['name'], 'email': request.form['email'], 'message': request.form['message']})
        flash("Your message has been sent", "success")
        return redirect(url_for('contact'))
    return render_template('contact.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
