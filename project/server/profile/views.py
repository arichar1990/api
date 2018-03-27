from flask import Blueprint, request, make_response, jsonify, g
from flask.views import MethodView
from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

from project.server import bcrypt, db
from project.server.models import Profile, User

import json


@auth.verify_password
def verify_token(email, password):
    def verify_password(username_or_token, password):
        # first try to authenticate by token
        user = User.decode_auth_token(username_or_token)
        if not user:
            # try to authenticate with username/password
            user = User.query.filter_by(username=username_or_token).first()
            if not user or not user.verify_password(password):
                return False
        g.user = user
        return True


class ProfileAPI(MethodView):
    """
    Profile Resource
    """

    def get(self):
        # get the auth token
        auth_header = request.headers.get('Authorization')
        auth_token = auth_header.split(" ")[1]

        resp = User.decode_auth_token(auth_token)
        if not isinstance(resp, str):
            user = User.query.filter_by(id=resp).first()
            profile = Profile.query.filter_by(user_id=user.id).first()
            responseObject = {
                'status': 'success',
                'data': {
                    'profile_name': profile.name
                }
            }
            return make_response(jsonify(responseObject)), 200

        else:
            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401


profile_blueprint = Blueprint('profile', __name__)

profile_view = ProfileAPI.as_view('profile_api')

profile_blueprint.add_url_rule(
    '/profile',
    view_func=profile_view,
    methods=['GET']
)
