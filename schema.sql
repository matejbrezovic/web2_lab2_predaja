-- psql -h localhost -U postgres -d web2_lab2 -f schema.sql

DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username varchar(255) UNIQUE NOT NULL,
    email varchar(255) UNIQUE NOT NULL,
    password varchar(255) NOT NULL,
    password_hash text NOT NULL
);

INSERT INTO users (username, email, password, password_hash) VALUES
  ('admin', 'admin@lab2.com', '123456', '$argon2id$v=19$m=65536,t=3,p=4$Jt7IYAQIp0t9ZwmmNGfWwQ$diVr4pxaZIt3yCAsN9ClNdCdVIqxHwrd51Fp5JAVgmA'),
  ('ana',   'ana@lab2.com',   'anin_turbo_jaki_password123', '$argon2id$v=19$m=65536,t=3,p=4$inLLBPMO6UTnjc6I/DUmlQ$wvHAUOtiiZveQPq3Nd7BFBGavsfxrCaxhUAQ4e7aBbU'),
  ('mirko', 'mirko@lab2.com', 'mirkov_super_password1234', '$argon2id$v=19$m=65536,t=3,p=4$HqXNaKiPxDfuCZD4rW2cOg$TxWz1rPw0YRDQ7oKnsUl69gwXapi7oNF0oX+iWJlzEI');
