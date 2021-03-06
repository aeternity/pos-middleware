#!/usr/bin/env python3
# version 0.2.1-DEV

import os
import sys
import logging
import json
import psycopg2
import psycopg2.extras
from psycopg2.pool import ThreadedConnectionPool
from contextlib import contextmanager
import datetime
import argparse
import threading
from queue import Queue
import time

# flask
from flask import Flask, jsonify, abort
from flask_socketio import SocketIO, emit

# aeternity
from aeternity import Config
from aeternity.signing import KeyPair
from aeternity.epoch import EpochClient

# key signing
from ecdsa import SECP256k1, VerifyingKey
import ecdsa
import base58
import base64
from hashlib import sha256


# also log to stdout because docker
root = logging.getLogger()
root.setLevel(logging.INFO)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

ch.setFormatter(formatter)
root.addHandler(ch)


logging.getLogger("aeternity.epoch").setLevel(logging.WARNING)
# logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
# logging.getLogger("engineio").setLevel(logging.ERROR)


# app secret
flask_secret = os.getenv('APP_SECRET')
access_key = os.getenv('POS_ACCESS_KEY')

epoch_node = os.getenv('EPOCH_NODE')
bar_wallet_private = os.getenv('WALLET_PRIV')
bar_wallet_address = os.getenv('WALLET_PUB')

BEER_PRICE = 1000


def fdate(dt):
    """format a date"""
    return dt.strftime('%d/%m/%Y – %H:%M:%S')


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
    def __init__(self, host, user, password, database, poolsize=10):
        connect_str = "dbname='{}' user='{}' host='{}' password='{}'".format(
            database, user, host, password)
        self.pool = ThreadedConnectionPool(1, poolsize, dsn=connect_str)

    @contextmanager
    def getcursor(self):
        con = self.pool.getconn()
        try:
            yield con.cursor(cursor_factory=psycopg2.extras.DictCursor)
        finally:
            con.commit()
            self.pool.putconn(con)

    def execute(self, query, params=()):
        """run a database update
        :param query: the query string
        :param params: the query parameteres
        """
        with self.getcursor() as c:
            try:
                c.execute(query, params)
            except Exception as e:
                logging.error(e)

    def select(self, query, params=(), many=False):
        """
        run a database update
        :param query: the query string
        :param params: the query parameteres
        """
        with self.getcursor() as c:
            try:
                # Insert a row of data
                c.execute(query, params)
                if many:
                    return c.fetchall()
                else:
                    return c.fetchone()
            except Exception as e:
                logging.error(e)


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

    logging.info(f"using node at {epoch_node}")

    # load the genesis keypair
    gp = bar_wallet_address
    gk = bar_wallet_private
    main_wallet = KeyPair.from_public_private_key_strings(gp, gk)

    return epoch, main_wallet


def verify_signature(sender, signature_b64, message):
    """
    :param sender: the sender address
    :param signature_b64: signature
    :param message: message
    """
    verified = False
    try:

        signature = base64.b64decode(signature_b64)

        sender_pub = base58.b58decode_check(sender[3:])
        logging.debug(
            f"sign  sender: {sender_pub} signature {signature} tx: {message}")

        vk = VerifyingKey.from_string(
            sender_pub[1:], curve=SECP256k1, hashfunc=sha256)

        verified = vk.verify(signature, bytearray(message, 'utf-8'), sigdecode=ecdsa.util.sigdecode_der)
    except Exception:
        verified = False

    logging.debug(
        "sign  sender: '{}' signature '{}' tx: {}, verified {}".format(
            sender, signature_b64, message, verified
        )
    )
    return verified

#    ______     ___      ______  ___  ____   ________  _________  _    ___
#  .' ____ \  .'   `.  .' ___  ||_  ||_  _| |_   __  ||  _   _  |(_) .'   `.
#  | (___ \_|/  .-.  \/ .'   \_|  | |_/ /     | |_ \_||_/ | | \_|__ /  .-.  \
#   _.____`. | |   | || |         |  __'.     |  _| _     | |   [  || |   | |
#  | \____) |\  `-'  /\ `.___.'\ _| |  \ \_  _| |__/ |   _| |_   | |\  `-'  /
#   \______.' `.___.'  `.____ .'|____||____||________|  |_____| [___]`.___.'
#


socketio = SocketIO()
app = Flask(__name__)
root.addHandler(app.logger)


@socketio.on('scan')
def handle_scan(access_key, tx_hash, tx_signature):
    # query the transactions
    global cash_register
    try:
        tx = cash_register.query_tx(tx_hash)
        if tx is None:
            # transaction not found
            reply = {
                "tx_hash": tx_hash,
                "success": False,
                "msg": f"Transaction {tx_hash} doesn't exists"
            }
            return reply

        # tx has been already validated
        if tx['scanned_at'] is not None:
            reply = {
                "tx_hash": tx_hash,
                "success": False,
                "msg": f"Transaction already executed at {fdate(tx['scanned_at'])}"
            }
            return reply

        if tx['amount'] < BEER_PRICE:
            reply = {
                "tx_hash": tx_hash,
                "success": False,
                "msg": f"Amount {tx['amount']} not enough, required {BEER_PRICE}"
            }
            return reply

        # verify_signature
        logging.debug(f"sign  sender: {tx['sender']} signature {tx_signature} tx: {tx_hash}")
        valid = verify_signature(tx['sender'], tx_signature, tx_hash)

        if not valid:
            # transaction is not valids
            reply = {
                "tx_hash": tx_hash,
                "success": False,
                "msg": f"Transaction signature mismatch"
            }
            return reply

        # transaction is good
        # update the record
        now = datetime.datetime.now()
        database.execute(
            'update transactions set tx_signature=%s, scanned_at = %s where tx_hash = %s',
            (tx_signature, now, tx_hash)
        )
        # get the wallet name
        wallet_name = tx['sender']
        row = database.select("select wallet_name from names where public_key = %s", (tx['sender'],))
        if row is not None:
            wallet_name = row['wallet_name']
        # reply
        beer_count = "{:.0f}".format(tx['amount'] / BEER_PRICE)
        reply = {
            "tx_hash": tx_hash,
            "success": True,
            "msg": f"Success! Serve {beer_count} beer(s) to {wallet_name} [amount {tx['amount']}]"
        }
    except Exception as e:
        logging.error(f"transaction scan {tx_hash} error {e}")
        reply = {
            "tx_hash": tx_hash,
            "success": False,
            "msg": f"Error!  ask for help!"
        }
    return reply


@socketio.on('was_beer_scanned')
def handle_was_beer_scanned(tx_hash):
    """check if the trasaction was scanned"""
    tx = database.select(
        "select * from transactions where tx_hash = %s", (tx_hash,))

    reply = {"scanned": False, "scanned_at": None}

    if tx is None:
        return reply

    if tx['scanned_at'] is not None:
        reply = {
            "scanned": True,
            "scanned_at": str(tx['scanned_at'])
        }

    return reply


@socketio.on('refund')
def handle_refund(access_key, wallet_address, amount):
    """
    refund an account from the bar account
    :param access_key: the shared secret to authenticate the pos
    :param wallet_address: the account to refound
    :param amount: the amount to move
    """
    reply = {"success": False, "tx_hash": None, "msg": None}
    # check the authorization
    if not authorize(access_key):
        msg = f"Unauthorized access for key '{access_key}'"
        logging.error(f"refund: {msg}")
        reply['msg'] = msg
        return reply
    # run the refund
    try:

        logging.debug(
            "from '{}', to '{}', amount '{}'".format(
                bar_wallet.get_address(), wallet_address, amount)
        )
        _, tx_hash = epoch.spend(keypair=bar_wallet,
                                 recipient_pubkey=wallet_address,
                                 amount=int(amount))

        wallet_name = wallet_address
        row = database.select("select wallet_name from names where public_key = %s", (wallet_address,))
        if row is not None:
            wallet_name = row['wallet_name']

        reply = {
            "success": True,
            "tx_hash": tx_hash,
            "msg": f"Success! Refunded {amount} aet to {wallet_name}"
        }
    except Exception as e:
        reply['msg'] = str(e)
    return reply


@socketio.on('set_bar_state')
def handle_set_bar_state(access_key, state):

    reply = {"success": False, "msg": None}
    # check the authorization
    if not authorize(access_key):
        reply['msg'] = f"Unauthorized access using key {access_key}, state {state}"
        logging.error(reply['msg'])
        return reply
    # run the update
    valid_states = ['open', 'closed', 'out_of_beers']
    if state in valid_states:
        database.execute("update state set state = %s, updated_at = NOW()", (state,))
        # BROADCAST new status
        emit('bar_state', {"state": state}, broadcast=True)
        logging.info(f"set_bar_state: new state {state}")
        reply = {"success": True, "msg": state}
    else:
        msg = f"Invalid invalid state {state}, allowed {','.join(valid_states)}"
        logging.error(msg)
        reply = {
            "success": False,
            "msg": msg
        }
    # reply to the sender
    return reply


@socketio.on('reset_bar')
def handle_reset_bar(access_key):
    """reset the local height of the database to"""
    reply = {"success": False, "msg": None}
    # check the authorization
    if not authorize(access_key):
        reply['msg'] = f"Unauthorized access using key {access_key}"
        logging.error(reply['msg'])
        return reply
    logging.info("RESET CHAINHEIGHT IN MIDDLEWARE DATABASE")
    database.execute("update pos_height set block_id = %s", (0,))
    # reply to the sender
    reply = {"success": True, "msg": "chain reset"}
    return reply


@socketio.on('get_bar_state')
def handle_get_bar_state():
    """reply to a bar state request"""
    row = database.select('select state from state limit 1')
    bar_state = row['state']
    # logging.info(f"retrieving bar state from database {bar_state}")
    return {"state": bar_state}


@socketio.on('get_name')
def handle_get_name(public_key):
    """reverse mapping for the account name"""
    row = database.select(
        'select wallet_name from names where public_key = %s', (public_key,))
    if row is not None:
        return {'name': row['wallet_name']}
    else:
        return {'name': None}


@app.after_request
def after_request(response):
    """enable CORS"""
    header = response.headers
    header['Access-Control-Allow-Origin'] = '*'
    return response


@app.route('/rest/name/<public_key>')
def rest_get_name(public_key):
    """reverse mapping for the account name"""
    row = database.select('select wallet_name from names where public_key = %s', (public_key,))
    if row is not None:
        reply = {"name": row['wallet_name']}
        return jsonify(reply)
    abort(404)


# global db variable
database = None


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
        :param orders_queue: orders chain queue
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
            interval = self.interval
            self.poll()

    def query_tx(self, tx_hash):
        """get a ttransaction from the database or None if it's not found"""

        q, p = "select * from transactions where tx_hash = %s", (tx_hash,)
        tx = self.db.select(q, p)
        if tx is None:
            self.poll_tx(tx_hash)
        tx = self.db.select(q, p)
        logging.debug(tx)
        return tx

    def insert_tx(self, block_id, pos_tx, recipient):
        """insert a transaction in the database if it match the bar account"""
        if recipient == self.bar_wallet.get_address():
            logging.info(f"FOUND BAR TRANSACTION {pos_tx[0]}")
            # insert block
            self.db.execute('insert into blocks(height) values (%s) on conflict(height) do nothing',
                            (block_id,))
            # record transaction
            self.db.execute('''insert into transactions (tx_hash, sender, amount, block_id, found_at)
                          values (%s,%s,%s,%s,%s) on conflict(tx_hash) do nothing''',
                            pos_tx)

    def poll_tx(self, tx_hash):
        """poll a specific transaction"""
        try:
            tx = self.epoch.get_transaction_by_transaction_hash(tx_hash)
            block_id = tx.block_height
            recipient = tx.tx.recipient
            pos_tx = (
                tx.hash,
                tx.tx.sender,
                tx.tx.amount,
                block_id,
                datetime.datetime.now()
            )
            self.insert_tx(block_id, pos_tx, recipient)
        except Exception as e:
            logging.info(f"transaction {tx_hash} lookup error {e}")
            raise e

    def poll(self):
        """do the polling"""
        try:
            logging.info('polling chain...')
            row = self.db.select("select block_id from pos_height")
            local_h = row['block_id']
            chain_h = self.epoch.get_height()

            logging.info(f"local height {local_h}, chain height {chain_h}")

            if local_h == chain_h:
                return

            while local_h < chain_h:
                block_step = min(10, chain_h - local_h)
                next_h = local_h + block_step
                logging.info(f"query tx in block range {local_h}-{next_h}")
                txs = self.epoch.get_transactions_in_block_range(
                    local_h, next_h, tx_types=['spend_tx'])

                for tx in txs:
                    pos_tx = (
                        tx.hash,
                        tx.tx.sender,
                        tx.tx.amount,
                        tx.block_height,
                        datetime.datetime.now()
                    )
                    self.insert_tx(tx.block_height, pos_tx,  tx.tx.recipient)
                    # push it into the orders queue to notify the frontend
                    # self.orders_queue.put({
                    #     'tx': pos_tx[0],
                    #     'sender': pos_tx[1],
                    #     'amount': pos_tx[2],
                    #     'block_h':  pos_tx[3],
                    #     'time':  pos_tx[4],
                    # })

                local_h = next_h
                # update the last polled block
                self.db.execute('update pos_height set block_id = %s', (local_h,))

        except Exception as e:
            logging.error("error polling the chain {}".format(e))


#     ______  ____    ____  ______     ______
#   .' ___  ||_   \  /   _||_   _ `. .' ____ \
#  / .'   \_|  |   \/   |    | | `. \| (___ \_|
#  | |         | |\  /| |    | |  | | _.____`.
#  \ `.___.'\ _| |_\/_| |_  _| |_.' /| \____) |
#   `.____ .'|_____||_____||______.'  \______.'
#


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

    app.config['SECRET_KEY'] = flask_secret
    global database
    database = PG(pg_host, pg_user, pg_pass, pg_db)
    global epoch
    global bar_wallet
    epoch, bar_wallet = get_aeternity()
    global cash_register
    cash_register = CashRegisterPoller(
        PG(pg_host, pg_user, pg_pass, pg_db),
        epoch,
        bar_wallet,
        orders_queue,
        interval=args.polling_interval)

    # backfround worker
    if not args.no_poll:
        cash_register.start()

    # start the app
    logging.info('start socket.io')
    socketio.init_app(app)
    socketio.run(app, host="0.0.0.0", max_size=10000, debug=False)


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
                    'names': ['-b', '--no-poll'],
                    'help':'only start the socketio service not the chain polling worker',
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
