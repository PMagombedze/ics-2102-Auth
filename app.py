from flask import Flask, render_template
from config import Config
from models import db, bcrypt

app = Flask(__name__)
app.config.from_object(Config)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/auth/login')
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
from password_checker import pc4

jwt = JWTManager(app)

# regex check email
def emailcheck(email):
    import re
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)


@app.route('/api/login', methods=['POST'])
def apilogin():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    user = User.query.filter((User.username == username) | (User.email == email)).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity=user.email)
        refresh_token = create_refresh_token(identity=user.email)
        return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200
    return jsonify({'message': 'Invalid credentials'}), 404

@app.route('/api/register', methods=['POST'])
def apiregister():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    user = User.query.filter((User.username == username) | (User.email == email)).first()
    if user:
        return jsonify({'message': 'User already exists'}), 400
    if not emailcheck(email):
        return jsonify({'message': 'Invalid email'}), 400
    if pc4.PasswordChecker(password):
        new_user = User(username=username, password=password, email=email)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User created'}), 201
    return jsonify({'message': 'Invalid credentials'}), 400

@app.route('/api/users', methods=['GET'])
@jwt_required()
def list_users():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user).first()
    if user and user.is_admin:
        users = User.query.all()
        return jsonify([user.to_dict() for user in users]), 200
    return jsonify({'message': 'Admin access required'}), 403

@app.route('/api/users/<string:id>', methods=['GET', 'DELETE', 'PUT'])
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
    user = User.query.filter_by(email=current_user).first()
    if user and user.is_admin:
        todos = Todo.query.all()
        return jsonify([todo.to_dict() for todo in todos]), 200
    return jsonify({'message': 'Admin access required'}), 403

@app.route('/api/todos/<string:id>', methods=['GET', 'DELETE', 'PUT'])
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
        todo.description = data.get('description', todo.description)
        todo.completed = data.get('completed', todo.completed)
        db.session.commit()
        return jsonify({'message': 'Todo updated'}), 200


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()