from flask import Flask, render_template
from config import Config
from models import db, bcrypt
import re

app = Flask(__name__)
app.config.from_object(Config)


@app.route('/')
def login():
    return render_template('login.html')

@app.route('/auth/register')
def register():
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin/dashboard')
def admin():
    return render_template('admin.html')

db.init_app(app)
bcrypt.init_app(app)

from flask import request, jsonify
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity, JWTManager, jwt_required
from models import db, User, Todo, bcrypt


jwt = JWTManager(app)

# regex check email
def emailcheck(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

# password checker
def passwordChecker(password):
    return re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", password)

# username validater
def usernamecheck(username):
    return len(username) > 6 and len(username) < 14

@app.route('/api/login', methods=['POST'])
def apilogin():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    user = User.query.filter((User.username == username) | (User.email == email)).first()
    if user and user.check_password(password):
        identity = email if email else username
        access_token = create_access_token(identity=identity)
        refresh_token = create_refresh_token(identity=identity)
        return jsonify({'access_token': access_token, 'refresh_token': refresh_token, 'is_admin': user.is_admin, "message": "logged in successfully"}), 200
    return jsonify({'message': 'Invalid credentials'}), 404

@app.route('/api/register', methods=['POST'])
def apiregister():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    # check if user already exists
    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        return jsonify({'message':'user already exists'}), 409
    if email and not emailcheck(email):
        return jsonify({'message': 'Invalid email format'}), 400
    if not usernamecheck(username):
        return jsonify({'message': 'Username too short or long'}), 400
    if not username and not email:
        return jsonify({'message': 'Username or email required'}), 400
    if not passwordChecker(password):
        return jsonify({'message': 'Password not secure'}), 400

    new_user = User(username=username, password=password, email=email)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created'}), 201

@app.route('/api/users', methods=['GET'])
@jwt_required()
def list_users():
    current_user = get_jwt_identity()
    user = User.query.filter((User.email == current_user) | (User.username == current_user)).first()
    if user and user.is_admin:
        users = User.query.all()
        return jsonify([user.to_dict() for user in users]), 200
    return jsonify({'message': 'Admin access required'}), 403

@app.route('/api/users/<int:id>', methods=['GET', 'DELETE', 'PUT'])
@jwt_required()
def user_detail(id):
    user = User.query.get(id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    if request.method == 'GET':
        return jsonify(user.to_dict()), 200

    if request.method == 'DELETE':
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted'}), 200

    if request.method == 'PUT':
        data = request.get_json()
        user.username = data.get('username', user.username)
        user.email = data.get('email', user.email)
        user.password = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')
        db.session.commit()
        return jsonify({'message': 'User updated'}), 200

@app.route('/api/todos', methods=['GET'])
@jwt_required()
def list_todos():
    current_user = get_jwt_identity()
    user = User.query.filter((User.email == current_user) | (User.username == current_user)).first()
    if user and user.is_admin:
        todos = Todo.query.all()
        return jsonify([todo.to_dict() for todo in todos]), 200
    return jsonify({'message': 'Admin access required'}), 403

# endpoint to allow user to post his todos
@app.route('/api/todos', methods=['POST'])
@jwt_required()
def create_todo():
    data = request.get_json()
    title = data.get('title')
    completed = data.get('completed')
    current_user = get_jwt_identity()
    user = User.query.filter((User.email == current_user) | (User.username == current_user)).first()
    if not title:
        return jsonify({'message': 'Title required'}), 400
    new_todo = Todo(title=title, completed=completed, user_id=user.id)
    db.session.add(new_todo)
    db.session.commit()
    return jsonify({'message': 'Todo created'}), 201


@app.route('/api/todos/<int:id>', methods=['GET', 'DELETE', 'PUT'])
@jwt_required()
def todo_detail(id):
    todo = Todo.query.get(id)
    if not todo:
        return jsonify({'message': 'Todo not found'}), 404

    if request.method == 'GET':
        return jsonify(todo.to_dict()), 200

    if request.method == 'DELETE':
        db.session.delete(todo)
        db.session.commit()
        return jsonify({'message': 'Todo deleted'}), 200

    if request.method == 'PUT':
        data = request.get_json()
        todo.title = data.get('title', todo.title)
        todo.completed = data.get('completed', todo.completed)
        db.session.commit()
        return jsonify({'message': 'Todo updated'}), 200


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)