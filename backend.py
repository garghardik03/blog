# from mailer import send_email_verification_mail
from flask_mail import Mail, Message
from flask import request
import hashlib
import pymongo
import smtplib


# Database Configuration parameters
MONGO_HOST_URL = 'mongodb://localhost:27017/'  # Example: "mongodb+srv://<DB-ID>.mongodb.net" or "mongodb://localhost:27017/"
MONGO_DATABASE_NAME = 'Blog'




# String Mixer
salt = 'owui4ht3uhtl2thloKSFB'  # Example: 'owui4ht3uhtl2thloKSFB'

def string_hash(text): 
    return hashlib.sha256(salt.encode() + text.encode()).hexdigest() + ':' + salt 



def register_auth_user(usr_fname, usr_lname, usr_eml, usr_pwd, usr_phone,sec_question,sec_answer):
    
    client = pymongo.MongoClient(MONGO_HOST_URL)
    db = client[MONGO_DATABASE_NAME]

    auth_users_col = db['auth_user'] # Collection for storing user data
    if auth_users_col.count_documents({'usr_eml': usr_eml}): # Checking if user already exists
        print(f'User with email {usr_eml} is already created.')
        return False

    hashed_pwd = string_hash(usr_pwd)

    new_user_data = {'usr_fname': usr_fname, 'usr_lname': usr_lname, 'usr_eml': usr_eml, 'usr_pwd': hashed_pwd,
                     'usr_phone': usr_phone, 'is_activated': 'False','profile_image':'download.jpeg','sec_question':sec_question,'sec_answer':sec_answer}
    ins = auth_users_col.insert_one(new_user_data)

    # Generating a validation key
    key, pkey = string_hash(usr_eml).split(':')

    # Setting the validation key in the DB
    verification_data = {
        'usr_eml': usr_eml,
        'key': key
    }
    verify_usr_eml_col = db['verify_usr_eml']
    ins = verify_usr_eml_col.insert_one(verification_data)
    client.close()
    link = request.host_url + f'verify/{key}' # host_url = http://  and verify is the route in app.py and key is the key generated above
    #Send Email verification mail
    #send_email_verification_mail(usr_eml, usr_fname, link)
    return ins.acknowledged


def check_auth_login(usr_eml, usr_pwd):

    client = pymongo.MongoClient(MONGO_HOST_URL)
    db = client[MONGO_DATABASE_NAME]

    auth_users_col = db['auth_user']
    hashed_pwd = string_hash(usr_pwd)
    search_data = {'usr_eml': usr_eml, 'usr_pwd': hashed_pwd}

    res = auth_users_col.count_documents(search_data)
    is_activated = auth_users_col.find_one(search_data) # Checking if user is activated or not

    if is_activated is None:
        return False
    is_activated = True
    client.close()

    if res == 1 and is_activated == True:
        # User verification successful
        return True
    else:
        # User verification failed
        return False


def verify_usr_eml(key):
    """
        Function to verify user's email address and activates the account so that user can login to the system.
    :param key: Email address of the user
    :return: Success/Failure
    """
    search_data = {
        'key': key,
    }
    client = pymongo.MongoClient(MONGO_HOST_URL)
    db = client[MONGO_DATABASE_NAME]

    verify_usr_eml_col = db['verify_usr_eml']
    auth_user_col = db['auth_user']
    res = verify_usr_eml_col.count_documents(search_data)
    if res == 1:
        usr_eml = verify_usr_eml_col.find_one(search_data, {'_id': 0, 'usr_eml': 1}).get('usr_eml')
        user_search_data = {
            'usr_eml': usr_eml
        }
        new_data = {
            'is_activated': 'True'
        }
        auth_user_col.update_one(user_search_data, {"$set": new_data})

        verify_usr_eml_col.delete_one(search_data)
        return f'User verification for {usr_eml} successful!!'
    else:
        return f'User verification failed!!'


    

