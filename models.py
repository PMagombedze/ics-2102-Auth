"""Todo list models
"""


# users model
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import random
import string

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    """User model
    """
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), nullable=True, default=''.join(random.choices(string.ascii_letters + string.digits, k=8)))
    password = db.Column(db.String(255), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    email = db.Column(db.String(255), nullable=False, default=f"user{random.randint(1, 1000)}@percy.com")
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    todos = db.relationship('Todo', backref='user', lazy=True)

    def __init__(self, username, password, email):
        self.username = username
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        self.email = email

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def __repr__(self):
        return f"<User {self.username}>"

# todos model
class Todo(db.Model):
    """Todo model
    """
    __tablename__ = "todos"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(255), nullable=True)
    completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'completed': self.completed,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'user_id': self.user_id
        }