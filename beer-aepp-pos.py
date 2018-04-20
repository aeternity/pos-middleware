#! /usr/bin/env python3

import os
import sys
import logging
import json
import psycopg2
import psycopg2.extras
import datetime
import argparse
import threading
from queue import Queue
import time

# flask
from flask import Flask, render_template, g
from flask_socketio import SocketIO, send, emit
from posapp import socketio, create_app

# aeternity
from aeternity import Config
from aeternity.signing import KeyPair
from aeternity.epoch import EpochClient
from aeternity.aens import AEName
from aeternity.exceptions import AException

# key signing
from ecdsa import SECP256k1, SigningKey, VerifyingKey
import ecdsa
import base58


# also log to stdout because docker
root = logging.getLogger()
root.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(msg)s')
ch.setFormatter(formatter)
root.addHandler(ch)


# app secret
flask_secret = os.getenv('APP_SECRET')
access_key = os.getenv('POS_ACCESS_KEY')

epoch_node = os.getenv('EPOCH_NODE')
bar_wallet_private = os.getenv('WALLET_PRIV')
bar_wallet_address = os.getenv('WALLET_PUB')


def authorize(request_key):
    """validate a request key"""
    if request_key == access_key:
        return True
    return False


def reload_settings():
    logging.info("reloading settings")
    global pg_host
    pg_host = os.getenv('POSTGRES_HOST')
    global pg_user
    pg_user = os.getenv('POSTGRES_USER')
    global pg_pass
    pg_pass = os.getenv('POSTGRES_PASSWORD')
    global pg_db
    pg_db = os.getenv('POSTGRES_DB')
    global pg_schema
    pg_schema = 'public'
    # app secret
    global flask_secret
    flask_secret = os.getenv('APP_SECRET')
    global access_key
    access_key = os.getenv('POS_ACCESS_KEY')

    global epoch_node
    epoch_node = os.getenv('EPOCH_NODE')
    global bar_wallet_private
    bar_wallet_private = os.getenv('WALLET_PRIV')
    global bar_wallet_address
    bar_wallet_address = os.getenv('WALLET_PUB')

#   ______   ______
#  |_   _ `.|_   _ \
#    | | `. \ | |_) |
#    | |  | | |  __'.
#   _| |_.' /_| |__) |
#  |______.'|_______/
#


class PG(object):
    def __init__(self, host, user, password, database):
        connect_str = f"dbname='{database}' user='{user}' host='{host}' password='{password}'"
        self.conn = psycopg2.connect(connect_str)

    def execute(self, query, params=()):
        """run a database update
        :param query: the query string
        :param params: the query parameteres
        """
        c = self.conn.cursor()
        try:
            # Insert a row of data
            c.execute(query, params)
            # Save (commit) the changes
            self.conn.commit()
        finally:
            c.close()

    def select(self, query, params=(), many=False):
        """
        run a database update
        :param query: the query string
        :param params: the query parameteres
        """
        c = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        try:
            # Insert a row of data
            c.execute(query, params)
            if many:
                return c.fetchall()
            else:
                return c.fetchone()
        finally:
            c.close()

#     ______  ____  ____       _       _____  ____  _____
#   .' ___  ||_   ||   _|     / \     |_   _||_   \|_   _|
#  / .'   \_|  | |__| |      / _ \      | |    |   \ | |
#  | |         |  __  |     / ___ \     | |    | |\ \| |
#  \ `.___.'\ _| |  | |_  _/ /   \ \_  _| |_  _| |_\   |_
#   `.____ .'|____||____||____| |____||_____||_____|\____|
#


def get_aeternity():
    """get the epoch client and the genesis keypair from config"""
    # configure epoch client in case we need it

    epoch = EpochClient(configs=Config(
        external_host=epoch_node,
        internal_host=f"{epoch_node}/internal",
        secure_connection=True
    ))

    # load the genesis keypair
    gp = bar_wallet_address
    gk = bar_wallet_private
    main_wallet = KeyPair.from_public_private_key_strings(gp, gk)

    return epoch, main_wallet


def verify_signature(sender, signature, message):
    sender_pub = base58.b58decode_check(sender[3:])
    vk = VerifyingKey.from_string(sender_pub, curve=SECP256k1)
    verified = vk.verify(signature, message,
                         sigdecode=ecdsa.util.sigdecode_der)
    return verified

#    ______     ___      ______  ___  ____   ________  _________  _    ___
#  .' ____ \  .'   `.  .' ___  ||_  ||_  _| |_   __  ||  _   _  |(_) .'   `.
#  | (___ \_|/  .-.  \/ .'   \_|  | |_/ /     | |_ \_||_/ | | \_|__ /  .-.  \
#   _.____`. | |   | || |         |  __'.     |  _| _     | |   [  || |   | |
#  | \____) |\  `-'  /\ `.___.'\ _| |  \ \_  _| |__/ |   _| |_   | |\  `-'  /
#   \______.' `.___.'  `.____ .'|____||____||________|  |_____| [___]`.___.'
#


@socketio.on('my_ping')
def handle_my_ping():
    # use this
    emit('my_ping_response', 'pong')
    # or this
    return 'pong'


@socketio.on('scan')
def handle_scan(access_key, tx_hash, tx_signature, sender):
    # query the transactions
    db = get_db()
    tx = db.select("select * from transactions where tx_hash = %s", tx_hash)

    if tx is None:
        # transaction not recorded // search the chain for it
        etx = g.epoch.get_transaction_by_transaction_hash(tx_hash)
        # if tx is not null (or no exception) then is ok
        if etx is None:
            reply = {
                "tx_hash": tx_hash,
                "valid": False,
                "msg": f"transaction doesn't exists"
            }
            # send(reply, json=True)
            return reply

    # tx has been already validated
    if tx['scanned_at'] is not None:
        reply = {
            "tx_hash": tx_hash,
            "valid": False,
            "msg": f"transaction executed at {tx['scanned_at']}"
        }
        # send(reply, json=True)
        return reply

    # verify_signature
    valid = verify_signature(sender, tx_signature, tx_hash)

    if not valid:
        # transaction is not valids
        reply = {
            "tx_hash": tx_hash,
            "valid": False,
            "msg": f"transaction signature mismatch"
        }
        # send(reply, json=True)
        return reply

    # transaction is good
    # update the record
    db.execute(
        'update transactions set tx_signature=%s, scanned_at = NOW() where tx_hash = %s',
        (tx_signature, tx_hash)
    )
    # reply
    reply = {
        "tx_hash": tx_hash,
        "valid": True,
        "msg": f"transaction executed at {tx['scanned_at']}"
    }
    # send(reply, json=True)
    return reply

@socketio.on('refund')
def handle_refund(access_key, wallet_address, amount):
    """
    refund an account from the bar account
    :param access_key: the shared secret to authenticate the pos
    :param wallet_address: the account to refound
    :param amount: the amount to move
    """
    # check the authorization
    if not authorize(access_key):
        logging.error(
            f"refund: unauthorized access using key {access_key}, wallet {wallet_address}, amount: {amount}")
        return
    # run the refund

    reply = {"success": False, "tx_hash": None, "msg": None}
    try:
        resp, tx_hash = g.epoch.spend(keypair=g.bar_wallet,
                                      recipient_pubkey=wallet_address,
                                      amount=amount)
        reply = {"success": True, "tx_hash": tx_hash, "msg": str(resp)}
    except Exception as e:
        reply['msg'] = str(e)
    emit('refund', json.dumps(reply))


@socketio.on('set_bar_state')
def handle_set_bar_state(access_key, state):
    print('handle_set_bar_state')
    # check the authorization
    if not authorize(access_key):
        logging.error(
            f"refund: unauthorized access using key {access_key}, state {state}")
        return
    # run the update
    db = get_db()
    reply = {"success": True, "msg": None}
    valid_states = ['open', 'closed', 'out_of_beers']
    if state in valid_states:
        db.execute(
            "update state set state = %s, updated_at = NOW()", (state,))
        # BROADCAST new status
        emit('bar_state', {"state": state}, broadcast=True, json=True)
        logging.info(f"set_bar_state: new state {state}")
    else:
        logging.error(
            f"set_bar_state: invalid invalid state {state}, allowd {','.join(valid_states)}")
        reply = {
            "success": False,
            "msg": f"invalid state {state}, only {','.join(valid_states)} are allowed"
        }
    # reply to the sender
    # send(reply, json=True)
    return reply


@socketio.on('get_bar_state')
def handle_get_bar_state():
    """reply to a bar state request"""
    print('get_bar_state')
    db = get_db()
    row = db.select('select state from state limit 1')
    # send({"state": row['state']}, json=True)
    emit('bar_state', {"state": row['state']}, json=True)
    return {"state": row['state']}


@socketio.on('get_name')
def handle_get_name(public_key):
    """reverse mapping for the account name"""
    db = get_db()
    row = db.select(
        'select wallet_name from names where public_key = %s', (public_key,))
    if row is not None:
        send({'name': row['wallet_name']}, json=True)
    else:
        send({'name': '404'}, json=True)

#   ____      ____   ___   _______     ___  ____   ________  _______
#  |_  _|    |_  _|.'   `.|_   __ \   |_  ||_  _| |_   __  ||_   __ \
#    \ \  /\  / / /  .-.  \ | |__) |    | |_/ /     | |_ \_|  | |__) |
#     \ \/  \/ /  | |   | | |  __ /     |  __'.     |  _| _   |  __ /
#      \  /\  /   \  `-'  /_| |  \ \_  _| |  \ \_  _| |__/ | _| |  \ \_
#       \/  \/     `.___.'|____| |___||____||____||________||____| |___|
#


class CashRegisterPoller(object):
    """
    Poll the bar account to look for transactions
    """

    def __init__(self,  db, epoch, bar_wallet, orders_queue, interval=15):
        """ Constructor
        :type db: PG
        :param db: object for database connection
        :type epoch: EpochClient
        :param epoch: client to interatct with the chain
        :type bar_wallet: KeyPair
        :param bar_wallet: contains the bar wallet
        :type orders_queue: Queue
        :param orders_queue: where to send the orders when they appear on the chain
        :type interval: int
        :param interval: Check interval, in seconds
        """
        self.interval = interval
        self.db = db
        self.epoch = epoch
        self.bar_wallet = bar_wallet
        self.orders_queue = orders_queue

    def start(self):
        """start the polling """
        # start the polling
        thread = threading.Thread(target=self.run, args=())
        thread.daemon = True                            # Daemonize thread
        thread.start()

    def run(self):
        interval = 0
        while True:
            # sleep at the beginning
            time.sleep(interval)
            # Do something
            print('Doing something imporant in the background')
            row = self.db.select("select max(height) as h from blocks")
            local_h = row['h']
            chain_h = self.epoch.get_height()

            logging.info(f"local height {local_h}, chain height {chain_h}")

            if local_h == chain_h:
                continue

            while local_h < chain_h:
                block_step = min(10, chain_h - local_h)
                next_h = local_h + block_step
                logging.info(f"query tx in block range {local_h}-{next_h}")
                txs = self.epoch.get_transactions_in_block_range(
                    local_h, next_h, tx_types=['spend_tx'])

                for tx in txs:
                    logging.info("block {:10} vsn:{:2} amount:{:4} from {} to {}".format(
                        tx.block_height,
                        tx.tx.vsn,
                        tx.tx.amount,
                        tx.tx.recipient,
                        tx.tx.sender
                    ))
                    if tx.tx.recipient == self.bar_wallet.get_address():
                        now = datetime.datetime.now()
                        pos_tx = (
                            tx.hash,
                            tx.tx.sender,
                            tx.tx.amount,
                            tx.block_height,
                            now
                        )
                        # insert block
                        self.db.execute(
                            'insert into blocks(height) values (%s) ON CONFLICT(height) DO NOTHING', (tx.block_height,))
                        # record transaction
                        self.db.execute(
                            'insert into transactions(tx_hash, sender, amount, block_id, found_at) values (%s,%s,%s,%s)', pos_tx)
                        # push it into the orders queue to notify the frontend
                        self.orders_queue.put({
                            'tx': pos_tx[0],
                            'sender': pos_tx[1],
                            'amount': pos_tx[2],
                            'block_h':  pos_tx[3],
                            'time':  pos_tx[4],
                        })

                local_h = next_h
                # insert block
                self.db.execute(
                    'insert into blocks(height) values (%s) on conflict(height) do nothing', (local_h,))
            interval = self.interval


#     ______  ____    ____  ______     ______
#   .' ___  ||_   \  /   _||_   _ `. .' ____ \
#  / .'   \_|  |   \/   |    | | `. \| (___ \_|
#  | |         | |\  /| |    | |  | | _.____`.
#  \ `.___.'\ _| |_\/_| |_  _| |_.' /| \____) |
#   `.____ .'|_____||_____||______.'  \______.'
#

def get_db():
    if not hasattr(g, 'db'):
        print('creating database singleton')
        pg_host = os.getenv('POSTGRES_HOST')
        pg_user = os.getenv('POSTGRES_USER')
        pg_pass = os.getenv('POSTGRES_PASSWORD')
        pg_db = os.getenv('POSTGRES_DB')
        g.db = PG(pg_host, pg_user, pg_pass, pg_db)
    return g.db


def cmd_start(args=None):
    if args.config is not None:
        # load the parameters from json
        # and set them as env var
        with open(args.config, 'r') as fp:
            config = json.load(fp)
            for k in config:
                os.environ[k] = config[k]
        reload_settings()

    # incoming orders will be queued here and sent to the pos client
    orders_queue = Queue()
    # open db connection
    pg_host = os.getenv('POSTGRES_HOST')
    pg_user = os.getenv('POSTGRES_USER')
    pg_pass = os.getenv('POSTGRES_PASSWORD')
    pg_db = os.getenv('POSTGRES_DB')

    app = create_app(secret_key=flask_secret)
    epoch, bar = get_aeternity()
    # backfround worker
    pg1 = PG(pg_host, pg_user, pg_pass, pg_db)
    crp = CashRegisterPoller(
        pg1, epoch, bar, orders_queue, interval=args.polling_interval)
    crp.start()
    # flask context
    with app.app_context():
        # within this block, current_app points to app.
        g.db = PG(pg_host, pg_user, pg_pass, pg_db)
        g.epoch = epoch
        g.bar_wallet = bar
        g.orders_queue = orders_queue

        # emit an order to the client
        def order_notify():
            order = orders_queue.get()
            logging.info("notifing frontend of new order")
            emit("order_received", access_key, order)
        # start the queue montior
        thread = threading.Thread(target=order_notify, args=())
        thread.daemon = True                            # Daemonize thread
        thread.start()

    socketio.run(app, host='0.0.0.0')


if __name__ == '__main__':
    cmds = [
        {
            'name': 'start',
            'help': 'start the beer aepp-pos-middelware',
            'opts': [
                {
                    'names': ['-c', '--config'],
                    'help':'use the configuration file instead of environment variables',
                    'default':None
                },
                {
                    'names': ['-b', '--bar-polling-only'],
                    'help':'only start the bar polling worker',
                    'action': 'store_true',
                    'default': False
                },
                {
                    'names': ['-p', '--polling-interval'],
                    'help':'polling interval in seconds',
                    'default': 15
                }
            ]
        }
    ]
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    subparsers.required = True
    subparsers.dest = 'command'
    # register all the commands
    for c in cmds:
        subp = subparsers.add_parser(c['name'], help=c['help'])
        # add the sub arguments
        for sa in c.get('opts', []):
            subp.add_argument(*sa['names'],
                              help=sa['help'],
                              action=sa.get('action'),
                              default=sa.get('default'))

    # parse the arguments
    args = parser.parse_args()
    # call the command with our args
    ret = getattr(sys.modules[__name__], 'cmd_{0}'.format(
        args.command.replace('-', '_')))(args)
