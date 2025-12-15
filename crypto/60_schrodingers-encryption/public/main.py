from magicrypt import schrodingers_cat
from person import Person

actual_flag = ""
try:
    with open("flag.txt", "r") as f:
        actual_flag = f.readline()[:-1]
except:
    actual_flag = "cuhk25ctf{test-flag}"

alice = Person("Alice")
bob = Person("Bob")

alice.say("Hey Bob, what is the flag? Please encrypt it since I know Malory is listening.")
bob.say("If Malory is listening, why do I still send the flag?")
alice.say("It's OK, Bob. You have invented a new encryption method which is secure, right?")
bob.say(f"Well... If you really want the encrypted flag, here you go... {schrodingers_cat(actual_flag)}")
alice.say("??? How do I decrypt it?")
bob.say("Only smart people with level 9999 tuning skills can decrypt this. Unfortunately, you only have level 9998 tuning skills.")
alice.say("Bruh ಠ_ಠ")

loop = True
while loop:
    bob.say("Now tell me the flag, I will check if you are right.")
    
    flag = input("Alice: ")
    bob.say("...")
    if flag == actual_flag:
        bob.say("Congratulations! You have decrypted the flag successfully!")
        loop = False
    else:
        bob.say("Sorry, wrong flag... Maybe the network is unstable so that's why you can't decrypt the flag...")
        bob.say(f"I will send my flag once again, here you go... {schrodingers_cat(actual_flag)}")
