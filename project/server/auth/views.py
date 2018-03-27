# project/server/auth/views.py

from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView

from project.server import bcrypt, db
from project.server.models import User, BlacklistToken, Profile
import datetime


class RegisterAPI(MethodView):
    """
    User Registration Resource
    """

    def post(self):
        # get the post data
        post_data = request.get_json()

        # check if screen name is in use
        user = User.query.filter_by(screen_name=post_data.get('ScreenName')).first()
        if user:
            responseObject = {
                'status': 'fail',
                'message': 'Screen name already in use. Please choose another.'
            }
            return make_response(jsonify(responseObject)), 202

        # check if user already exists
        user = User.query.filter_by(email=post_data.get('Email')).first()
        if not user:
            try:
                user = User(
                    email=post_data.get('Email'),
                    password=post_data.get('Password'),
                    screen_name=post_data.get('ScreenName')
                )

                # insert the user
                db.session.add(user)
                db.session.commit()
                db.session.add(Profile(user_id=user.id, name=user.screen_name))
                db.session.commit()

                auth_token, exp = user.encode_auth_token(user.id)
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                    'auth_token': auth_token.decode(),
                    'expires': exp
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                # print(e)
                responseObject = {
                    'status': 'fail',
                    'message': 'Some error occurred. Please try again.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return make_response(jsonify(responseObject)), 202


class LoginFormAPI(MethodView):
    """
    User Login Resource
    """
    def post(self):
        # check the grant_type
        if ('grant_type' not in request.form) or (request.form['grant_type'] != 'password'):

            responseObject = {
                'status': 'fail',
                'message': 'unsupported_grant_type'
            }

            return make_response(jsonify(responseObject)), 400

        try:
            username = request.form['username']
            password = request.form['password']

            # try to fetch the user data by screen_name
            user = User.query.filter_by(
                screen_name=username
            ).first()

            # if that fails, try email
            if not user:
                user = User.query.filter_by(
                    email=username
                ).first()

            if user and bcrypt.check_password_hash(user.password, password):
                auth_token, exp = user.encode_auth_token(user.id)
                if auth_token:
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token.decode(),
                        'expires': exp
                    }
                    return make_response(jsonify(responseObject)), 200

            elif user:
                responseObject = {
                    'status': 'fail',
                    'message': 'Incorrect email or password.'
                }
                return make_response(jsonify(responseObject)), 405

            else:
                responseObject = {
                    'status': 'fail',
                    'message': 'User does not exist.'
                }
                return make_response(jsonify(responseObject)), 404

        except Exception as e:
            print(e)
            responseObject = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(responseObject)), 500


class LoginAPI(MethodView):
    """
    User Login Resource
    """
    def post(self):
        # get the post data
        post_data = request.get_json()
        try:
            # fetch the user data
            if post_data.get('Email') == '':
                user = User.query.filter_by(
                    screen_name=post_data.get('ScreenName')
                ).first()
            else:
                user = User.query.filter_by(
                    email=post_data.get('Email')
                ).first()

            if user and bcrypt.check_password_hash(
                user.password, post_data.get('Password')
            ):
                auth_token, exp = user.encode_auth_token(user.id)
                if auth_token:
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token.decode()
                    }
                    return make_response(jsonify(responseObject)), 200

            elif user:
                responseObject = {
                    'status': 'fail',
                    'message': 'Incorrect email or password.'
                }
                return make_response(jsonify(responseObject)), 405

            else:
                responseObject = {
                    'status': 'fail',
                    'message': 'User does not exist.'
                }
                return make_response(jsonify(responseObject)), 404
        except Exception as e:
            print(e)
            responseObject = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(responseObject)), 500


class LogoutAPI(MethodView):
    """
    Logout Resource
    """
    def post(self):
        # get auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                # mark the token as blacklisted
                blacklist_token = BlacklistToken(token=auth_token)
                try:
                    # insert the token
                    db.session.add(blacklist_token)
                    db.session.commit()
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged out.'
                    }
                    return make_response(jsonify(responseObject)), 200
                except Exception as e:
                    responseObject = {
                        'status': 'fail',
                        'message': e
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403


class UserAPI(MethodView):
    """
    User Resource
    """
    def get(self):
        # get the auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                user = User.query.filter_by(id=resp).first()
                responseObject = {
                    'status': 'success',
                    'data': {
                        'user_id': user.id,
                        'email': user.email,
                        'admin': user.admin,
                        'registered_on': user.registered_on
                    }
                }
                return make_response(jsonify(responseObject)), 200
            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401


auth_blueprint = Blueprint('auth', __name__)

# define the API resources
registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
login_form_view = LoginFormAPI.as_view('login_form_api')
user_view = UserAPI.as_view('user_api')
logout_view = LogoutAPI.as_view('logout_api')

# add Rules for API Endpoints
auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/login',
    view_func=login_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/Token',
    view_func=login_form_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/status',
    view_func=user_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/logout',
    view_func=logout_view,
    methods=['POST']
)
