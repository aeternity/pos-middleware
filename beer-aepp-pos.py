#! /usr/bin/env python3

from flask import Flask, render_template
from flask_socketio import SocketIO, send, emit


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)


@socketio.on('scan')
def handle_scan(arg1):
    print('received args: ' + arg1 + arg2 + arg3)


if __name__ == '__main__':
    socketio.run(app)
