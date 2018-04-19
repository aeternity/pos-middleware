\connect posapp

CREATE TABLE IF NOT EXISTS blocks (
  height integer PRIMARY KEY
);

INSERT INTO blocks(height) VALUES(0) ON CONFLICT(height) DO NOTHING;

CREATE TABLE IF NOT EXISTS transactions (
  tx_hash char(60) PRIMARY KEY, 
  tx_signature varchar(200),
  sender varchar(150),
  amount integer,
  scanned_at TIMESTAMP DEFAULT NULL,
  found_at TIMESTAMP DEFAULT NOW(),
  block_id integer REFERENCES blocks
);

CREATE TABLE IF NOT EXISTS state (
  id bool PRIMARY KEY DEFAULT TRUE,
  state varchar(100) DEFAULT 'open',
  updated_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO state(id) VALUES (true);


CREATE TABLE IF NOT EXISTS names (
  wallet_name varchar(33) PRIMARY KEY,
  public_key varchar(150)
);

CREATE UNIQUE INDEX names_public_key_idx ON names(public_key);
