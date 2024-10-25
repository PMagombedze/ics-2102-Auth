"""Restful API
"""

from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity, JWTManager, jwt_required
from flask_restful import Resource, reqparse, Api
from models import db, User, Todo, bcrypt
from password_checker import pc4
import emailcheck as email

api = Api()
jwt = JWTManager()

# user login
class UserLogin(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=False, help='Username is required')
        parser.add_argument('email', type=str, required=False, help='Email is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        args = parser.parse_args()
        user = User.query.filter((User.username == args['username']) | (User.email == args['email'])).first()
        if user and user.check_password(args['password']): 
            access_token = create_access_token(identity=user.email)
            refresh_token = create_refresh_token(identity=user.email)
            return {'access_token': access_token, 'refresh_token': refresh_token}, 200
        return {'message': 'Invalid credentials'}, 404

# user registration
class UserRegistration(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=False, help='Username is required')
        parser.add_argument('email', type=str, required=False, help='Email is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        args = parser.parse_args()
        user = User.query.filter((User.username == args['username']) | (User.email == args['email'])).first()
        if user:
            return {'message': 'user already exists'}, 400
        if not email.check(args['email']):
            return {'message': 'Invalid email'}, 400
        if pc4.PasswordChecker(args['password']):
            db.session.add(User(args['username'], args['password'], args['email']))
            db.session.commit()
            return {'message': 'user created'}, 201
        return {'message': 'Invalid credentials'}, 400

# list all users
class UserList(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        user = User.query.filter_by(email=current_user).first()
        if user and user.is_admin:
            users = User.query.all()
            return [user.to_dict() for user in users], 200
        return {'message': 'Admin access required'}, 403

# get user, delete user, update user
class UserDetail(Resource):
    @jwt_required()
    def get(self, id):
        user = User.query.get(id)
        if user:
            return user.to_dict(), 200
        return {'message': 'User not found'}, 404

    @jwt_required()
    def delete(self, id):
        user = User.query.get(id)
        if user:
            db.session.delete(user)
            db.session.commit()
            return {'message': 'User deleted'}, 200
        return {'message': 'User not found'}, 404

    @jwt_required()
    def put(self, id):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=False, help='Username is required')
        parser.add_argument('email', type=str, required=False, help='Email is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        args = parser.parse_args()
        user = User.query.get(id)
        if user:
            user.username = args['username']
            user.email = args['email']
            user.password = bcrypt.generate_password_hash(args['password']).decode('utf-8')
            db.session.commit()
            return {'message': 'User updated'}, 200
        return {'message': 'User not found'}, 404

# list all todos
class TodoList(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        user = User.query.filter_by(email=current_user).first()
        if user and user.is_admin:
            todos = Todo.query.all()
            return [todo.to_dict() for todo in todos], 200
        return {'message': 'Admin access required'}, 403

# get todo, delete todo, update todo
class TodoDetail(Resource):
    @jwt_required()
    def get(self, id):
        todo = Todo.query.get(id)
        if todo:
            return todo.to_dict(), 200
        return {'message': 'Todo not found'}, 404

    @jwt_required()
    def delete(self, id):
        todo = Todo.query.get(id)
        if todo:
            db.session.delete(todo)
            db.session.commit()
            return {'message': 'Todo deleted'}, 200
        return {'message': 'Todo not found'}, 404

    @jwt_required()
    def put(self, id):
        parser = reqparse.RequestParser()
        parser.add_argument('title', type=str, required=False, help='Title is required')
        parser.add_argument('description', type=str, required=False, help='Description is required')
        parser.add_argument('completed', type=bool, required=False, help='Completed is required')
        args = parser.parse_args()
        todo = Todo.query.get(id)
        if todo:
            todo.title = args['title']
            todo.description = args['description']
            todo.completed = args['completed']
            db.session.commit()
            return {'message': 'Todo updated'}, 200
        return {'message': 'Todo not found'}, 404

# api endpoints
api.add_resource(UserLogin, '/api/login')
api.add_resource(UserRegistration, '/api/register')
api.add_resource(UserList, '/api/users')
api.add_resource(UserDetail, '/api/users/<str:id>')
api.add_resource(TodoList, '/api/todos')
api.add_resource(TodoDetail, '/api/todos/<str:id>')
