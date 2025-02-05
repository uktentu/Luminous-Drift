from flask import Flask, request, jsonify, session
from functools import wraps
from sql.User import User, UserDB, UserError

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'
user_db = UserDB()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Login required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Login required'}), 401
        user = user_db.get_user_by_username(session['username'])
        if not user or not user.admin:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        user = User(
            firstName=data['firstName'],
            lastName=data['lastName'],
            username=data['username'],
            email=data['email'],
            password=data['password']
        )
        user_db.create_user(user)
        return jsonify(user.to_dict()), 201
    except (KeyError, UserError) as e:
        return jsonify({'error': str(e)}), 400

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        user = user_db.authenticate_user(data['username'], data['password'])
        if user:
            session['username'] = user.username
            return jsonify(user.to_dict())
        return jsonify({'error': 'Invalid credentials'}), 401
    except KeyError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.pop('username', None)
    return jsonify({'message': 'Logged out'})

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    user = user_db.get_user_by_username(session['username'])
    return jsonify(user.to_dict())

@app.route('/reset-password', methods=['POST'])
@login_required
def reset_password():
    try:
        data = request.json
        user = user_db.get_user_by_username(session['username'])
        if user_db.authenticate_user(user.username, data['old_password']):
            user_db.update_password(user.username, data['new_password'])
            return jsonify({'message': 'Password updated successfully'})
        return jsonify({'error': 'Invalid old password'}), 401
    except KeyError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/users', methods=['GET'])
@admin_required
def get_users():
    users = user_db.get_all_users()
    return jsonify([user.to_dict() for user in users])

@app.route('/admins', methods=['GET'])
@admin_required
def get_admins():
    users = user_db.get_filtered_users(admin=True)
    return jsonify([user.to_dict() for user in users])

@app.route('/non_admins', methods=['GET'])
@admin_required
def get_non_admins():
    users = user_db.get_filtered_users(admin=False)
    return jsonify([user.to_dict() for user in users])

@app.route('/active_users', methods=['GET'])
@admin_required
def get_active_users():
    users = user_db.get_filtered_users(active=True)
    return jsonify([user.to_dict() for user in users])

@app.route('/inactive_users', methods=['GET'])
@admin_required
def get_inactive_users():
    users = user_db.get_filtered_users(active=False)
    return jsonify([user.to_dict() for user in users])

if __name__ == '__main__':
    app.run(debug=True)