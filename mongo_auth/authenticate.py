import jwt
import bcrypt
import streamlit as st
from datetime import datetime, timedelta
import extra_streamlit_components as stx
from pymongo import MongoClient
import os
from .hasher import Hasher
from .utils import generate_random_pw
from .exceptions import CredentialsError, ForgotError, RegisterError, ResetError, UpdateError
import re
import requests
import json
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from pprint import pprint

class Authenticate:
    def __init__(self, cookie_name: str, key: str, cookie_expiry_days: int=30):
        self.mongo_uri = os.environ['MONGO_AUTH']
        self.cookie_name = cookie_name
        self.key = key
        self.cookie_expiry_days = cookie_expiry_days
        self.cookie_manager = stx.CookieManager()
        self.db_name = 'IntelligenceHub'

        if 'name' not in st.session_state:
            st.session_state['name'] = None
        if 'authentication_status' not in st.session_state:
            st.session_state['authentication_status'] = None
        if 'email' not in st.session_state:
            st.session_state['email'] = None
        if 'logout' not in st.session_state:
            st.session_state['logout'] = None
        self.preauthorized = {'emails': []}

    def _token_encode(self) -> str:
        return jwt.encode({'name': st.session_state['name'],
                           'email': st.session_state['email'],
                           'exp_date': self.exp_date}, self.key, algorithm='HS256')

    def _token_decode(self) -> str:
        try:
            return jwt.decode(self.token, self.key, algorithms=['HS256'])
        except:
            return False

    def _set_exp_date(self) -> str:
        return (datetime.utcnow() + timedelta(days=self.cookie_expiry_days)).timestamp()

    def _check_pw(self) -> bool:
        client = MongoClient(self.mongo_uri)
        db = client[self.db_name]
        users = db['users']
        user = users.find_one({'email': self.email})
        client.close()
        if user is not None:
            hashed_pw = user['password']
            return bcrypt.checkpw(self.password.encode(), hashed_pw.encode())
        return False

    def _check_cookie(self):
        self.token = self.cookie_manager.get(self.cookie_name)
        if self.token is not None:
            self.token = self._token_decode()
            if self.token is not False:
                if not st.session_state['logout']:
                    if self.token['exp_date'] > datetime.utcnow().timestamp():
                        if 'name' and 'email' in self.token:
                            st.session_state['name'] = self.token['name']
                            st.session_state['email'] = self.token['email']
                            st.session_state['authentication_status'] = True

    def _check_credentials(self, inplace: bool=True) -> bool:
        print('checking credentials....')
        client = MongoClient(self.mongo_uri)
        db = client[self.db_name]
        users = db['users']
        user = users.find_one({'email': self.email})
        client.close()
        if user is not None:
            try:
                if self._check_pw():
                    st.session_state['verified'] = user.get('verified', False)
                    if inplace:
                        st.session_state['name'] = user['name']
                        self.exp_date = self._set_exp_date()
                        self.token = self._token_encode()
                        self.cookie_manager.set(self.cookie_name, self.token,
                                                expires_at=datetime.now() + timedelta(days=self.cookie_expiry_days))
                        st.session_state['authentication_status'] = True
                    else:
                        return True
                else:
                    if inplace:
                        st.session_state['authentication_status'] = False
                    else:
                        return False
            except Exception as e:
                print(e)
        else:
            if inplace:
                st.session_state['authentication_status'] = False
            else:
                return False
        return False  # Ensure the function always returns a boolean

    def login(self, form_name: str, location: str='main') -> tuple:
        print('login')
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if not st.session_state['authentication_status'] or st.session_state.get('verified') in [None, False]:
            self._check_cookie()
            self.email = st.session_state.get('email')
            if st.session_state.get('verified') in [None, False]:
                if st.session_state.get('authentication_status') in [None, False]:
                    if location == 'main':
                        login_form = st.form('Login')
                    elif location == 'sidebar':
                        login_form = st.sidebar.form('Login')

                    login_form.subheader(form_name)
                    self.email = login_form.text_input('Email').lower()
                    st.session_state['email'] = self.email
                    self.password = login_form.text_input('Password', type='password')

                    if login_form.form_submit_button('Login'):
                        self._check_credentials()

        return st.session_state['name'], st.session_state['authentication_status'], st.session_state['email']

    def logout(self, button_name: str, location: str='main', key='123'):
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            if st.button(button_name, key=key):
                self.cookie_manager.delete(self.cookie_name)
                st.session_state['logout'] = True
                st.session_state['name'] = None
                st.session_state['email'] = None
                st.session_state['authentication_status'] = None
                st.session_state['verified'] = None
        elif location == 'sidebar':
            if st.sidebar.button(button_name, key=key):
                self.cookie_manager.delete(self.cookie_name)
                st.session_state['logout'] = True
                st.session_state['name'] = None
                st.session_state['email'] = None
                st.session_state['authentication_status'] = None
                st.session_state['verified'] = None

    def _update_password(self, email: str, password: str):
        hashed_password = Hasher([password]).generate()[0]
        client = MongoClient(self.mongo_uri)
        db = client[self.db_name]
        users = db['users']
        user_records = users.find_one({'email': self.email})
        if user_records:
            users.update_one({"email": self.email}, {"$set": {"password": hashed_password}})
        client.close()

    def reset_password(self, email: str, form_name: str, location: str='main') -> bool:
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")

        reset_password_form = None
        if location == 'main':
            reset_password_form = st.form('Reset password')
        elif location == 'sidebar':
            reset_password_form = st.sidebar.form('Reset password')

        reset_password_form.subheader(form_name)
        self.email = email.lower()
        self.password = reset_password_form.text_input('Current password', type='password')
        new_password = reset_password_form.text_input('New password', type='password')
        new_password_repeat = reset_password_form.text_input('Repeat password', type='password')
        if reset_password_form.form_submit_button('Reset'):
            client = MongoClient(self.mongo_uri)
            db = client[self.db_name]
            users = db['users']
            user_info = users.find_one({'email': self.email})
            client.close()
            if user_info is not None:
                if self._check_credentials(inplace=False):
                    if len(new_password) > 0:
                        if new_password == new_password_repeat:
                            if self.password != new_password:
                                self._update_password(self.email, new_password)
                                return True
                            else:
                                raise ResetError('New and current passwords are the same')
                        else:
                            raise ResetError('Passwords do not match')
                    else:
                        raise ResetError('No new password provided')
                else:
                    raise ResetError('Wrong password')
            else:
                raise CredentialsError
        else:
            return False

    def _register_credentials(self, email: str, name: str, password: str, preauthorization: bool, needs: bool=False, postal_code: str=None):
        user_credentials = {
            'email': email,
            'name': name,
            'password': Hasher([password]).generate()[0],
            'verified': False,
            'needs': needs,
            'postal_code': postal_code,
            'created': datetime.now()
        }
        client = MongoClient(self.mongo_uri)
        db = client[self.db_name]
        users = db['users']
        users.insert_one(user_credentials)
        client.close()

        try:
            configuration = sib_api_v3_sdk.Configuration()
            configuration.api_key['api-key'] = os.getenv("BREVO_API_KEY")

            api_instance = sib_api_v3_sdk.ContactsApi(sib_api_v3_sdk.ApiClient(configuration))
            
            # Check if contact already exists
            try:
                contact_info = api_instance.get_contact_info(email)
                print(f"Contact already exists: {contact_info}")
            except ApiException as e:
                if e.status == 404:
                    # Contact does not exist, create it
                    contact = sib_api_v3_sdk.CreateContact(
                        email=email, 
                        attributes={"FIRSTNAME": name.split(' ')[0]}, 
                        list_ids=[2], 
                        update_enabled=False
                    )
                    api_instance.create_contact(contact)
                else:
                    print(f"Exception when checking contact: {e}")

        except ApiException as e:
            print(f"Exception when calling ContactsApi: {e}")

        # Call FastAPI email verification service after successfully adding to users and Brevo list
        verification_url = os.getenv("VERIFICATION_URL")
        data = {'email': email, 'id': '123'}
        response = requests.post(verification_url, json=data)
        if response.status_code != 200:
            print(f"Failed to send verification email: {response.text}")


    def register_user(self, form_name: str, location: str='main', preauthorization=True) -> bool:
        def validate_email(email):
            email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            return re.match(email_regex, email) is not None

        if preauthorization:
            if not self.preauthorized:
                raise ValueError("preauthorization argument must not be None")
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            register_user_form = st.form('Register user')
        elif location == 'sidebar':
            register_user_form = st.sidebar.form('Register user')

        register_user_form.subheader(form_name)
        new_email = register_user_form.text_input('Email')
        new_name = register_user_form.text_input('Name')
        new_password = register_user_form.text_input('Password', type='password')
        new_password_repeat = register_user_form.text_input('Repeat password', type='password')
        postal_code = register_user_form.text_input('Your postal code')
        needs = register_user_form.radio('I want to', ["Buy", "Sell", "Both", "I am a realtor"])

        client = MongoClient(self.mongo_uri)
        db = client[self.db_name]
        users = db['users']
        if register_user_form.form_submit_button('Register'):
            if validate_email(new_email):
                if len(new_email) and len(new_email) and len(new_name) and len(new_password) > 0:
                    if users.find_one({'email': new_email}) is None:
                        if new_password == new_password_repeat:
                            if preauthorization:
                                if self.preauthorized.find_one({'email': new_email}) is not None:
                                    self._register_credentials(new_email, new_name, new_password, preauthorization, needs, postal_code)
                                    client.close()
                                    return True
                                else:
                                    client.close()
                                    raise RegisterError('User not preauthorized to register')
                            else:
                                self._register_credentials(new_email, new_name, new_password, preauthorization, needs, postal_code)
                                client.close()
                                return True
                        else:
                            client.close()
                            raise RegisterError('Passwords do not match')
                    else:
                        client.close()
                        raise RegisterError('Email already taken')
                else:
                    client.close()
                    raise RegisterError('Please enter an email, name, and password')
            else:
                client.close()
                raise RegisterError('Please enter a valid email address')

    def _set_random_password(self, email: str) -> str:
        self.random_password = generate_random_pw()
        hashed_password = Hasher([self.random_password]).generate()[0]
        client = MongoClient(self.mongo_uri)
        db = client[self.db_name]
        users = db['users']
        users.update_one({'email': email}, {'$set': {'password': hashed_password}})
        client.close()
        return self.random_password

    def forgot_password(self, form_name: str, location: str='main') -> tuple:
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            forgot_password_form = st.form('Forgot password')
        elif location == 'sidebar':
            forgot_password_form = st.sidebar.form('Forgot password')

        forgot_password_form.subheader(form_name)
        email = forgot_password_form.text_input('email').lower()

        if forgot_password_form.form_submit_button('Submit'):
            if len(email) > 0:
                client = MongoClient(self.mongo_uri)
                db = client[self.db_name]
                users = db['users']
                user = users.find_one({'email': email})
                client.close()
                if user:
                    return email, user['email'], self._set_random_password(email)
                else:
                    return False, None, None
            else:
                raise ForgotError('email not provided')
        return None, None, None

    def _get_email(self, key: str, value: str) -> str:
        client = MongoClient(self.mongo_uri)
        db = client[self.db_name]
        users = db['users']
        user = users.find_one({key: value})
        client.close()
        if user:
            return user['email']
        return False

    def forgot_email(self, form_name: str, location: str='main') -> tuple:
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            forgot_email_form = st.form('Forgot email')
        elif location == 'sidebar':
            forgot_email_form = st.sidebar.form('Forgot email')

        forgot_email_form.subheader(form_name)
        email = forgot_email_form.text_input('Email')

        if forgot_email_form.form_submit_button('Submit'):
            if len(email) > 0:
                return self._get_email('email', email), email
            else:
                raise ForgotError('Email not provided')
        return None, email

    def _update_entry(self, email: str, key: str, value: str):
        client = MongoClient(self.mongo_uri)
        db = client[self.db_name]
        users = db['users']
        users.update_one({'email': email}, {'$set': {key: value}})
        client.close()

    def update_user_details(self, email: str, form_name: str, location: str='main') -> bool:
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            update_user_details_form = st.form('Update user details')
        elif location == 'sidebar':
            update_user_details_form = st.sidebar.form('Update user details')

        update_user_details_form.subheader(form_name)
        self.email = email.lower()
        field = update_user_details_form.selectbox('Field', ['name', 'email']).lower()
        new_value = update_user_details_form.text_input('New value')
        client = MongoClient(self.mongo_uri)
        db = client[self.db_name]
        users = db['users']
        if update_user_details_form.form_submit_button('Update'):
            if len(new_value) > 0:
                user_record = users.find_one({'email': self.email})
                print(user_record)
                if new_value != user_record[field]:
                    users.update_one({'email': self.email}, {'$set': {field: new_value}})
                    client.close()
                    if field == 'name':
                        st.session_state['name'] = new_value
                        self.exp_date = self._set_exp_date()
                        self.token = self._token_encode()
                        self.cookie_manager.set(self.cookie_name, self.token,
                                                expires_at=datetime.now() + timedelta(days=self.cookie_expiry_days))
                    client.close()
                    return True
                else:
                    client.close()
                    raise UpdateError('New and current values are the same')
            if len(new_value) == 0:
                client.close()
                raise UpdateError('New value not provided')
