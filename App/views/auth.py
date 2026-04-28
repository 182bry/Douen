from flask import Blueprint, jsonify, redirect, request, url_for
from flask_jwt_extended import current_user, jwt_required, set_access_cookies, unset_jwt_cookies

from App.controllers.auth import login

auth_views = Blueprint('auth_views', __name__, template_folder='../templates')


@auth_views.route('/login', methods=['GET'])
def login_page():
    return redirect(url_for('main.dashboard'))


@auth_views.route('/login', methods=['POST'])
def login_action():
    data = request.form
    token = login(data['username'], data['password'])
    if not token:
        return redirect(url_for('main.dashboard'))
    response = redirect(url_for('main.dashboard'))
    set_access_cookies(response, token)
    return response


@auth_views.route('/logout', methods=['GET'])
def logout_action():
    response = redirect(url_for('main.dashboard'))
    unset_jwt_cookies(response)
    return response


@auth_views.route('/api/login', methods=['POST'])
def user_login_api():
    data = request.json
    token = login(data['username'], data['password'])
    if not token:
        return jsonify(message='Bad username or password.'), 401
    response = jsonify(access_token=token)
    set_access_cookies(response, token)
    return response


@auth_views.route('/api/logout', methods=['GET'])
def logout_api():
    response = jsonify(message='Logged out.')
    unset_jwt_cookies(response)
    return response


@auth_views.route('/api/identify', methods=['GET'])
@jwt_required()
def identify_user():
    return jsonify({'message': f'username: {current_user.username}, id: {current_user.id}'})
