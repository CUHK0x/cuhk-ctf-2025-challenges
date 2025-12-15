#!/usr/local/bin/python3
def shiki_chan(user_input):
    blocked = ["chocolate", "mint", "strawberry", "flavour", "flavor", "cookie", "cream", "COOKIE", "CREAM", "+", "import", "os", "eval", "exec", "flag", "and", "map", "chr", "txt", "lower", "swapcase", "str", "string", "casefold", "capitalize", "title", "bytes", "decode"]
    # hints: What is the function of the + operator in Python?
    for word in blocked:
        if word in user_input.casefold():
            print("Too direct! Plz try again.")
            return
    try:
        print(eval(user_input))
    except Exception as e:
        print(f"Shiki-chan got confused: {e}")

while True:
    print("Shiki chan~ What do you like?")
    user_input = input("> ")
    shiki_chan(user_input)
    # globals() # hints: use built-in function to solve it.

