from SquigglyStuff import Point, Squiggle, deserialize_point
from Crypto.Random.random import randint
import time

# Do you like Bitcoins?
# Introducing the Bitcoin Squiggle! (｡♥‿♥｡)
squiggle = Squiggle(0, 7, 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1)
G = Point(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def trust():
    return input("> ").strip().lower()[0] == 'y'

def main():
    start_time = time.time()

    d = randint(2, order - 1)
    Q = squiggle.mul(d, G)

    print("Ciallo～(∠・ω< )⌒★")
    print("I know a secret number d, and I can tell you Q.")
    print("Q:", Q)

    print("I really know the value of d! (≧▽≦)")
    print("Do you trust me? 0v0")
    continue_protocol = not trust()
    round_no = 0

    while continue_protocol:
        if round_no == 10:
            print("You don't trust me? (╯°□°）╯︵ ┻━┻")
            print("I am a trustworthy person, I swear! (｡•́︿•̀｡)")
            print("Me go cry in the corner now... (ಥ﹏ಥ)")
            print("Bye! (╯︵╰,)")
            return
        round_no += 1
        
        print("Why no trust me? QAQ")
        print("OK fine, I will prove it to you.")
        print("The protocol goes as follows:")
        print(r"1. Nah I am too lazy to write it down, just read the code by yourself... ¯\_(ツ)_/¯")
        print("2. Yes, CTF players should know how to read code. AwA")
        # UwU
        
        print("Now give me C1 and C2! >w<")
        print("I don't want C4, I don't wanna get exploded! :3")
        C1 = deserialize_point(input("C1: ").strip())
        C2 = deserialize_point(input("C2: ").strip())

        print("The thing you need is", squiggle.add(C2, squiggle.mul(-d, C1)))

        print("Now do you trust me? OwO")
        continue_protocol = not trust()

    print("I knew you would trust me, I am a trustworthy person after all! ^_^")
    print("Now, it's time for you to prove that to me! (¬‿¬)")
    print("I can also prove that you don't know the secret number! UwU")

    for i in range(10):
        print(f"Round {i + 1}:")
        P = squiggle.mul(randint(1, order - 1), G)
        k = randint(1, order - 1)
        C1 = squiggle.mul(k, G)
        C2 = squiggle.add(P, squiggle.mul(k, Q))
        print("C1:", C1)
        print("C2:", C2)

        print("Now tell me a secret!")
        secret = deserialize_point(input("Secret: ").strip())
        if secret == P:
            print("You got lucky...")
        else:
            print("Haha, told you that you don't know the secret number!")
            print("I am always right! (¬‿¬)")
            return

    print("Well... Umm... Err... I guess you are really lucky...")

    if time.time() - start_time >= 30:
        print("It is a bit late now, I need to go to bed... (｡•́︿•̀｡)")
        print("I am sleeeeeepy... zzzzz... (￣o￣) . z Z Z")
        print("https://tinyurl.com/trustworthy-person-UwU")
        return

    flag = open("flag.txt", "r").read()

    print("Fine, here is what you wanted to know:", flag)
    print("You made me a non-trustworthy person! >.<")
    print("Hope you are happy now! (｡•́︿•̀｡)")
    print("Bye! (╯°□°）╯︵ ┻━┻")

if __name__ == "__main__":
    main()