CREATE DATABASE posapp;
GRANT ALL PRIVILEGES ON DATABASE posapp TO postgres;

\connect posapp

CREATE TABLE blocks (
  height integer PRIMARY KEY
);

INSERT INTO blocks(height) VALUES(0);

CREATE TABLE transactions (
  th char(60) PRIMARY KEY,
  sender varchar(150),
  amount integer,
  scanned_at TIMESTAMP DEFAULT NULL,
  block_id integer REFERENCES blocks
);

CREATE TABLE state (
  id bool PRIMARY KEY DEFAULT TRUE,
  state varchar(100) DEFAULT 'active'
);