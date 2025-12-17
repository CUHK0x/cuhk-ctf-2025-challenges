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

INSERT INTO users (username, password, flag) VALUES ('OwO', 'YouCanNeverBypassMeUwU', 'cuhk25ctf{OwO_Can_5me11_Stink_Use_621_Rule_1n_Ur_Hackin_9rind_UwU}');
