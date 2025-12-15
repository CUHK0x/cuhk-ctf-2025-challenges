import asyncio
import shlex

# Commands that will be 'hidden leaks'
LEAK_COMMANDS = ["📜", "💭"]

# Cooking recipe (sequence of commands required)
COOKING_RECIPE = [
    ("chop", "🍅"),
    ("crack", "🥚"),
    ("mix", "🥚"),
    ("cook", "🥚", "60"),
    ("cook", "🍅", "60"),
    ("wait", "10"),
    ("serve", "🍽️"),
]

# Easter egg (hint) when specific emojis are entered
EASTER_EGG_PARTS = [
    "✨ Hint 1: VGhlIHJlY2lwZSBzdGFydHMgd2l0aCBjaG9wcGluZyBzb21ldGhpbmcgcmVkLg==",
    "✨ Hint 2: RWdncyBuZWVkIHRvIGJlIGNyYWNrZWQgYmVmb3JlIG1peGluZy4=",
    "✨ Hint 3: Q29vayB0aW1lcyBtYXR0ZXIuIEFsbCBpbmdyZWRpZW50cyBuZWVkIHRvIGNvb2sgNjBz",
    "✨ Hint 4: RG9u4oCZdCBmb3JnZXQgdG8gc2VydmUgb24gYSBwbGF0ZSBhZnRlciAxMCBzZWNvbmQh",
    "✨ Hint 5: VGhlcmUgc2hvdWxkIGJlIHRvdGFsIDcgc3RlcHMgYmVmb3JlIHlvdSBjYW4gZ2V0IHRoZSBmbGFnLg=="
]

# --- Helper data ---

# Map command emojis to verbs; map ingredient emojis to themselves (so recipe matches)
FIXED_MAPPING = {
    "🐱": "cat",
    "🔪": "chop",
    "🔥": "cook",
    "⏳": "wait",
    "📜": "leak1",
    "💭": "leak2",
    "👊": "crack",
    "🫱": "serve",
    "🥣": "mix",
    "🪄": "Magic~"
}

FOOD_NAMES = {
    "🍅": "tomato",
    "🥚": "egg",
    "🍽️": "plate"
}

def pretty_name(ingredient):
    return f"{ingredient} ({FOOD_NAMES.get(ingredient, 'unknown')})"


VALID_INGREDIENTS = {"🍅", "🥚", "🍽️"}
ACTION_EMOJIS = {"🔪": "chop", "🔥": "cook", "⏳": "wait", "👊": "crack",
"🫱": "serve", "🥣": "mix"}  # for "{emoji} nothing" echo

class EmojiShellSession:
    def __init__(self, seed=None):
        self.mapping = FIXED_MAPPING
        self.leak_commands = LEAK_COMMANDS
        self.state = {
            "ingredients": set(),
            "cooked": set(),
            "waited": 0,
            "step_index": 0,
            "history": []
        }

    def leak_partial_mapping(self, cmd):
        keys = list(self.mapping.keys())
        half = len(keys) // 2
        if cmd == "📜":
            leaked = {k: self.mapping[k] for k in keys[:half]}
        elif cmd == "💭":
            leaked = {k: self.mapping[k] for k in keys[half:]}
        else:
            leaked = {}
        return leaked
    
    def parse_emoji_command(self, line):
        # Emojis are whitespace-separated; shlex not needed here
        return line.strip().split()

    def execute_command(self, tokens):
        if not tokens:
            return ""
        steps_done = self.state["step_index"]
        steps_total = len(COOKING_RECIPE)
        steps_left = steps_total - steps_done
        progress_msg = f"Progress: Step {steps_done}/{steps_total} ✅ ({steps_left} steps left)"

        # Leak commands (checked before mapping)
        if tokens[0] in self.leak_commands:
            leaked = self.leak_partial_mapping(tokens[0])
            lines = [f"{k} = {v}" for k, v in leaked.items()]
            return "Leaked mappings:\n" + "\n".join(lines)
        
        # Hints (Easter egg)
        if tokens[0] == "🪄":
            hint = EASTER_EGG_PARTS[self.state.get("hint_index", 0)]
            self.state["hint_index"] = (self.state.get("hint_index", 0) + 1) % len(EASTER_EGG_PARTS)
            return hint
        
        # History log
        if tokens[0] == "📝":
            if not self.state["history"]:
                return "History log is empty. No steps has been done yet."
            else:
                history_text = "\n".join(f"{i+1}. {h}" for i, h in enumerate(self.state["history"]))
                step_done = self.state["step_index"]
                steps_total = len(COOKING_RECIPE)
                return f"📝 Your progress so far ({step_done}/{steps_total}):\n{history_text}"
                
        # fake flag :)
        if tokens[0] == "🚩":
            return "cuhk25ctf{tH1s_iS_4_faK3_F1ag:)}"

        # Map emojis to verbs/ingredients; leave unknowns as-is (numbers etc.)
        cmds = [self.mapping.get(t,t) for t in tokens]
        cmd_name = cmds[0]

        # exit / help / hint
        if cmd_name == "exit":
            return "__EXIT__"
        if cmd_name == "hint":
            return "Try the magic emoji! Remember CTRL + C in terminal will kill the connection with the server.\nTry use CTRL + Shift + C / V."
        if cmd_name == "help":
            return "Try emoji like: 🔪 🍅  | 🔥 🍅 30 | ⏳ 10   •  Leaks: 📜, 💭   •  exit"

        # "{emoji} nothing" rule for action with missing/invalid args
        # We must echo the ORIGINAL emoji token for the action (tokens[0])
        if cmd_name in {"chop", "cook", "mix", "crack", "serve"}:
            # need at least one ingredient for chop/mix/stir, and ingredient+time for cook
            if len(cmds) < 2:
                return f"{tokens[0]} nothing\n{progress_msg}"
            ingredient = cmds[1]
            if ingredient not in VALID_INGREDIENTS:
                return f"{tokens[0]} nothing\n{progress_msg}"
            if cmd_name == "cook":
                if len(cmds) < 3 or not cmds[2].isdigit():
                    return f"{tokens[0]} nothing. Timing matters\n{progress_msg}"
                    
        # Error message for non-emoji input
        for t in tokens:
            if t not in FIXED_MAPPING and t not in VALID_INGREDIENTS and not t.isdigit():
                return f"'{t}' is not valid! Only specific emojis & text commands are accepted."
            
        # Recipe step checking (only chop/cook/wait advance the recipe)
        step = self.state["step_index"]
        if step < len(COOKING_RECIPE):
            expected = COOKING_RECIPE[step]
            if tuple(cmds[:len(expected)]) != expected:
                return "Wrong step or command. Try again."
                
            self.state["step_index"] += 1
            action = expected[0]
            
            # Save to history
            pretty_step = " ".join(tokens)  # keep emojis
            self.state["history"].append(pretty_step)
            
            # update progress after each success
            step_done = self.state["step_index"]
            steps_total = len(COOKING_RECIPE)
            steps_left = steps_total - step_done
            progress_msg = f"Progress: Step {step_done}/{steps_total} ✅ ({steps_left} steps left)"
            
                
            if action == "chop":
                return f"You chopped {pretty_name(expected[1])}!\n{progress_msg}"
            elif action == "cook":
                return f"Cooking {pretty_name(expected[1])} for {expected[2]} seconds...\n{progress_msg}"
            elif action == "wait":
                return f"Waited {expected[1]} seconds...\n{progress_msg}"
            elif action == "crack":
                return f"You cracked {pretty_name(expected[1])}!\n{progress_msg}"
            elif action == "mix":
                return f"You mixed {pretty_name(expected[1])}!\n{progress_msg}"
            elif action == "serve": #serve command 
                if expected[1] != "🍽️":
                    return "You need a plate to serve a dish!"
                else:
                    return "Dish served!\nSecret recipe complete! Here is your secret: cuhk25ctf{3gG&t0M9To5tIrfRy_1s_tHa_BEST}"
    
        else:
            return "Error!"

# --- Server ---

async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"New connection from {addr}")

    session = EmojiShellSession(seed=hash(addr))

    welcome = "Welcome to Fchui’s Emoji Shell! 🍳\nTry 📜 or 💭 to learn commands. Type exit to quit. Type help for help.\nGlcr uvag sbe uvag. Gel 📝 sbe uvfgbel ybt!\n"
    writer.write(welcome.encode())
    await writer.drain()
    
    try:
        while True:
            writer.write(b"> ")
            await writer.drain()
            data = await reader.readline()
            if not data:
                break
            line = data.decode().strip()
            if not line:
                continue

            output = session.execute_command(session.parse_emoji_command(line))
            if output == "__EXIT__":
                writer.write(b"Bye!\n")
                await writer.drain()
                break
            writer.write((output + "\n").encode())
            await writer.drain()
    finally:
        session.state["history"].clear()

        writer.close()
        await writer.wait_closed()
        print(f"Connection closed {addr}")

async def main():
    server = await asyncio.start_server(handle_client, '0.0.0.0', 12345)
    #print("Emoji shell server running on port 25031")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
