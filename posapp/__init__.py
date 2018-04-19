from flask import Flask
from flask_socketio import SocketIO


socketio = SocketIO()

def create_app(secret_key=''):
  app = Flask(__name__)
  socketio.init_app(app)
  app.config['SECRET_KEY'] = secret_key
  
  return app
