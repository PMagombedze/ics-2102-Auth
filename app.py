from flask import Flask, render_template
from config import Config
from api import api, jwt
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

with app.app_context():
    db.init_app(app)
    db.create_all()
    jwt.init_app(app)
    bcrypt.init_app(app)
    api.init_app(app)

if __name__ == '__main__':
    app.run()