CREATE DATABASE posapp;
GRANT ALL PRIVILEGES ON DATABASE posapp TO postgres;

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
  block_id integer REFERENCES blocks
);

CREATE TABLE IF NOT EXISTS state (
  id bool PRIMARY KEY DEFAULT TRUE,
  state varchar(100) DEFAULT 'open',
  updated_at TIMESTAMP DEFAULT NOW()
);