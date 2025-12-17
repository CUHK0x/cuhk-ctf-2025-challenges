import requests

url = "http://localhost:25027"

r = requests.get(url + "/uploads/1/flag1.txt")

print(r.text)