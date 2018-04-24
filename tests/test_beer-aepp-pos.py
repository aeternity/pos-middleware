import sys
import os
import base64
import json
import time
import unittest

import requests
import coverage

from posapp import create_app, socketio


class PosappTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.ctx = self.app.app_context()
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    def test_socketio(self):
        client = socketio.test_client(self.app)

        # clear old socket.io notifications
        client.get_received()

        # ping user via socketio to make it be back online
        client.emit('ping')
        # self.assertEqual(user.online, True)
        recvd = client.get_received()
        self.assertEqual(len(recvd), 1)
        self.assertEqual(recvd[0]['args'][0]['class'], 'User')
        self.assertEqual(recvd[0]['args'][0]['model']['nickname'], 'foo')
        self.assertEqual(recvd[0]['args'][0]['model']['online'], True)


if __name__ == '__main__':

    unittest.main()