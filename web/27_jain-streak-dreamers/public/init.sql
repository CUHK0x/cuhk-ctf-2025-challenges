CREATE TABLE IF NOT EXISTS things (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    content TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);

INSERT INTO users (username, password) VALUES ('streakers', '$argon2id$v=19$m=65536,t=2,p=1$MGd5SjFKOEREeA$6T+Nh2l2rmAK4KE6HyzBMSEl9iqVWmul19N33UgjJng');
