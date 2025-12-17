DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS captchas;
DROP TABLE IF EXISTS uploads;

CREATE TABLE users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    flag TEXT DEFAULT 'cuhk24ctf{Did_U_BURP_to_GET_FLAG_frum_gammAAAAAAAAAAAAAAAAAAAAAAAAAmon_asdflk;dkjfkl;j}'
);

CREATE TABLE captchas (
    id TEXT PRIMARY KEY,
    captcha TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE uploads (
    id TEXT PRIMARY KEY,
    owned_by TEXT NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (username, password, flag) VALUES ('OwO', 'YouCanNeverBypassMeUwU', 'cuhk25ctf{this_is_test_flag_1}');
