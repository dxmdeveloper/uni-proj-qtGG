 -- DROP TABLE IF EXISTS users;
CREATE TABLE IF NOT EXISTS users  (
    id        BIGSERIAL PRIMARY KEY,
    username  VARCHAR(30),
    email     VARCHAR(80),
    pass_hash VARCHAR(138)
);
