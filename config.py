"""App configurations
"""

import os
from dotenv import load_dotenv
from datetime import timedelta


load_dotenv()


class Config:
    """Base config class."""
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=float(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES')))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(hours=float(os.environ.get('JWT_REFRESH_TOKEN_EXPIRES')))