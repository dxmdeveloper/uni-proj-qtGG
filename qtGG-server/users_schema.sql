 -- DROP TABLE IF EXISTS users;
CREATE TABLE IF NOT EXISTS users  (
    id          BIGSERIAL PRIMARY KEY,
    username    VARCHAR(30) NOT NULL,
    email       VARCHAR(80) NOT NULL,
    pass_hash   VARCHAR(138) NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active      BOOLEAN NOT NULL DEFAULT TRUE
);

-- DROP TABLE IF EXISTS key_exchange;
CREATE TABLE IF NOT EXISTS key_exchange (
    id           BIGSERIAL PRIMARY KEY,
    step         INT NOT NULL DEFAULT 0,
    req_user     BIGINT NOT NULL,
    key_owner    BIGINT,
    conversation BIGINT NOT NULL,
    enc_key      VARCHAR(5000),
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (req_user) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (key_owner) REFERENCES users(id) ON DELETE CASCADE
);

-- DROP TABLE IF EXISTS conversations;
CREATE TABLE IF NOT EXISTS conversations (
    id           BIGSERIAL PRIMARY KEY,
    user1        BIGINT NOT NULL,
    user2        BIGINT NOT NULL,
    FOREIGN KEY (user1) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (user2) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT uniq_users UNIQUE (user1, user2)
);

-- DROP TABLE IF EXISTS messages;
CREATE TABLE IF NOT EXISTS messages (
    id           BIGSERIAL PRIMARY KEY,
    conversation BIGINT NOT NULL,
    sender       BIGINT NOT NULL,
    message      VARCHAR(500) NOT NULL,
    send_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (conversation) REFERENCES conversations(id) ON DELETE CASCADE
);

