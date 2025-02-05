from flask import Flask, request, jsonify, session
from sql.User import User, UserDB, UserError

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a secure secret key
user_db = UserDB()

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
def logout():
    session.pop('username', None)
    return jsonify({'message': 'Logged out'})

@app.route('/profile', methods=['GET'])
def profile():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    user = user_db.get_user_by_username(session['username'])
    return jsonify(user.to_dict())

@app.route('/users', methods=['GET'])
def get_users():
    users = user_db.get_all_users()
    return jsonify([user.to_dict() for user in users])

@app.route('/admins', methods=['GET'])
def get_admins():
    users = user_db.get_filtered_users(admin=True)
    return jsonify([user.to_dict() for user in users])

@app.route('/non_admins', methods=['GET'])
def get_non_admins():
    users = user_db.get_filtered_users(admin=False)
    return jsonify([user.to_dict() for user in users])

@app.route('/active_users', methods=['GET'])
def get_active_users():
    users = user_db.get_filtered_users(active=True)
    return jsonify([user.to_dict() for user in users])

@app.route('/inactive_users', methods=['GET'])
def get_inactive_users():
    users = user_db.get_filtered_users(active=False)
    return jsonify([user.to_dict() for user in users])

if __name__ == '__main__':
    app.run(debug=True)