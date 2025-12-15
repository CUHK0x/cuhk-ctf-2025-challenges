import time


class Person:
    def __init__(self, name):
        self.name = name

    def say(self, message):
        print(f"{self.name}: {message}", flush=True)
        time.sleep(0.5)
