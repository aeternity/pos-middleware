#! /usr/bin/env python3

import os
import sys
import logging
import json
from flask import Flask, render_template, g
from flask_socketio import SocketIO, send, emit
import psycopg2
import datetime
import argparse

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


pg_host = os.getenv('POSTGRES_HOST')
pg_user = os.getenv('POSTGRES_USER')
pg_pass = os.getenv('POSTGRES_PASSWORD')
pg_db = os.getenv('POSTGRES_DB')
pg_schema = 'public'

# app secret
flask_secret = os.getenv('APP_SECRET')
access_key = os.getenv('POS_ACCESS_KEY')

epoch_node = os.getenv('EPOCH_NODE')
bar_wallet_private = os.getenv('WALLET_PRIVATEKEY')
bar_wallet_address = os.getenv('WALLET_PUBLICKEY')


app = Flask(__name__)
socketio = SocketIO(app)


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
    bar_wallet_private = os.getenv('WALLET_PRIVATEKEY')
    global bar_wallet_address
    bar_wallet_address = os.getenv('WALLET_PUBLICKEY')

#   ______   ______
#  |_   _ `.|_   _ \
#    | | `. \ | |_) |
#    | |  | | |  __'.
#   _| |_.' /_| |__) |
#  |______.'|_______/
#


def db_conn():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'db'):
        connect_str = f"dbname='{pg_db}' user='{pg_user}' host='{pg_host}' password='{pg_pass}'"
        # use our connection values to establish a connection
        g.db = psycopg2.connect(connect_str)
        # row factory to get rows as dicts

        def dict_factory(cursor, row):
            d = {}
            for idx, col in enumerate(cursor.description):
                d[col[0]] = row[idx]
            return d
        g.db.row_factory = dict_factory

    return g.db


def db_execute(query, params):
    """run a database update
    :param query: the query string
    :param params: the query parameteres
    """
    c = db_conn().cursor()
    try:
        # Insert a row of data
        c.execute(query, params)
        # Save (commit) the changes
        db_conn().commit()
    finally:
        c.close()


def db_query(query, params=(), many=False):
    """
    run a database update
    :param query: the query string
    :param params: the query parameteres
    """
    c = db_conn().cursor()
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
    if not hasattr(g, 'epoch'):
        g.epoch = EpochClient(configs=Config(
            external_host=epoch_node,
            internal_host=f"{epoch_node}/internal",
            secure_connection=True
        ))

    # load the genesis keypair
    if not hasattr(g, 'main_wallet'):
        gp = bar_wallet_address
        gk = bar_wallet_private
        g.main_wallet = KeyPair.from_public_private_key_strings(gp, gk)

    return g.epoch, g.main_wallet


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


@socketio.on('ping')
def handle_ping():
    send("pong !!!!")


@socketio.on('scan')
def handle_scan(access_key, tx_hash, tx_signature, sender):
    # query the transactions
    tx = db_query("select * from transactions where tx_hash = ?", tx_hash)

    if tx is None:
        # transaction not recorded // search the chain for it
        epoch, _ = get_aeternity()
        etx = epoch.get_transaction_by_transaction_hash(tx_hash)
        # if tx is not null (or no exception) then is ok
        if etx is None:
            reply = {
                "tx_hash": tx_hash,
                "valid": False,
                "msg": f"transaction doesn't exists"
            }
            send(reply, json=True)
            return

    # tx has been already validated
    if tx['scanned_at'] is not None:
        reply = {
            "tx_hash": tx_hash,
            "valid": False,
            "msg": f"transaction executed at {tx['scanned_at']}"
        }
        send(reply, json=True)
        return

    # verify_signature
    valid = verify_signature(sender, tx_signature, tx_hash)

    if not valid:
        # transaction is not valids
        reply = {
            "tx_hash": tx_hash,
            "valid": False,
            "msg": f"transaction signature mismatch"
        }
        send(reply, json=True)
        return

    # transaction is good
    # update the record
    db_execute(
        'update transactions set tx_signature=?, scanned_at = NOW() where tx_hash = ?',
        (tx_signature, tx_hash)
    )
    # reply
    reply = {
        "tx_hash": tx_hash,
        "valid": True,
        "msg": f"transaction executed at {tx['scanned_at']}"
    }
    send(reply, json=True)


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
    epoch, bar_keypair = get_aeternity()

    reply = {"success": False, "tx_hash": None, "msg": None}
    try:
        resp, tx_hash = epoch.spend(keypair=bar_keypair,
                                    recipient_pubkey=wallet_address,
                                    amount=amount)
        reply = {"success": True, "tx_hash": tx_hash, "msg": str(resp)}
    except Exception as e:
        reply['msg'] = str(e)
    emit('refund', json.dumps(reply))


@socketio.on('set_bar_state')
def handle_set_bar_state(access_key, state):

    # check the authorization
    if not authorize(access_key):
        logging.error(
            f"refund: unauthorized access using key {access_key}, state {state}")
        return
    # run the update
    reply = {"success": True, "msg": None}
    valid_states = ['open', 'closed', 'out_of_beers']
    if state in valid_states:
        db_execute("update state set state = ?, updated_at = NOW()", (state,))
        # BROADCAST new status
        emit('bar_state', json.dumps({"state": state}), broadcast=True)
        logging.info(f"set_bar_state: new state {state}")
    else:
        logging.error(
            f"set_bar_state: invalid invalid state {state}, allowd {','.join(valid_states)}")
        reply = {
            "success": False,
            "msg": f"invalid state {state}, only {','.join(valid_states)} are allowed"
        }
    # reply to the sender
    send(reply, json=True)


@socketio.on('get_bar_state')
def handle_get_bar_state():
    """reply to a bar state request"""
    row = db_query('SELECT state FROM state LIMIT 1')
    emit('bar_state_reply', json.dumps(json.dumps({"state": row['state']})))

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
    #
    app.config['SECRET_KEY'] = flask_secret
    socketio.run(app)


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
