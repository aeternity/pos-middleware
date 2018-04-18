# Beer AEPP middelware

handles transaction validation to the beer POS

the app port is the number `5000`


# SocketIO events

all the reply are with json format

#### Test event
```
event: 'ping'
params: None
reply: 'pong'
```

#### Scan event (pos app only)
triggered when the 'bartender' scans a transaction from a customer phone

```
event: 'scan'
params: 
  - access_key   : shared secret to authorize the pos app
  - tx_hash      : scanned transaction hash
  - tx_signature : signature of the transaction hash
  - sender       : sender public key
reply: 
  - tx_hash : transaction hash
  - valid   : true if the order is vaild, false otherwise
  - msg     : additional messages
```


#### Refund event (pos app only)
triggered when the 'bartender' refund an account 

```
event: 'refund'
params:
  - access_key     : shared secret to authorize the pos app
  - wallet_address : the address public key to refund
  - amount         : the amount of money to refund
reply:
  - tx_hash : transaction hash
  - success : true if the refund succeded, false otherwise
  - msg     : additional messages
```

#### Set_bar_state event (pos app only)
triggered by the 'bartender' to change the status of the bar.
the change will also send a broadcast to all the connected beer apps

broadcast message: `bar_state(state:new_state)` 

```
event: 'set_bar_state'
params: 
  - access_key : shared secret to authorize the pos app
  - state      : the new state of the bar possile values are open,closed,out_of_beer
reply: 'pong'
  - success : true if the state change succeded, false otherwise
  - msg     : additional messages
```

#### Get_bar_state event (beer app)
get the current state of the bar

```
event: 'get_bar_state'
params: None
reply: 
  - state : the current state of the bar
```

#### Get_name event (?)
lookup a name of an account by public key

```
event: 'get_name'
params: 
  - address : aeternity account address
reply: 
  - name : the name of the address or 404 if not found
``