import requests

url = "http://localhost:25027"

# The whole uploads folder was served publicly, so we can just get the flag there
r = requests.get(url + "/uploads/1/flag1.txt")

print(r.text)