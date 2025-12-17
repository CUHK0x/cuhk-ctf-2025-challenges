from flask import Flask, request, render_template, make_response, redirect, url_for
import base64
import hashlib
import hmac

app = Flask(__name__)

# better instruction (remind use base64 to set cookie value)
# secret key use no. of cookie avoid brute force
# 'chocolate' + 'chip' + 'yummy' + token
# chip hint needs change: WHat is x?

SECRET = "cookie_monster_1337"
FINAL_SECRET = b"super_secret_key_34" #stored in byte

def generate_token(cookie1, cookie2, cookie3):
    return hashlib.md5((cookie1 + cookie2 + cookie3 + SECRET).encode()).hexdigest()

def generate_signed_cookie(user):
    return hmac.new(FINAL_SECRET, user.encode(), hashlib.sha256).hexdigest()

@app.route('/')
def index():
    response = make_response()

    # Retrieve cookies
    cookie1 = request.cookies.get('cookie1')
    cookie2 = request.cookies.get('cookie2')
    cookie3 = request.cookies.get('cookie3')
    token = request.cookies.get('token')

# Initialize cookies if missing
    if cookie1 is None or cookie2 is None or cookie3 is None or token is None:
        if cookie1 is None:
            response.set_cookie('cookie1', '?', path='/')
        if cookie2 is None:
            response.set_cookie('cookie2', '?', path='/')
        if cookie3 is None:
            response.set_cookie('cookie3', '?', path='/')
        if token is None:
            encoded_secret = base64.b64encode(SECRET.encode()).decode()
            response.set_cookie('token', encoded_secret, path='/')

        response.set_data(render_template('index.html',
            stage=1,
            message="Challenge started! Set your cookie value to begin. Check Console for hints.",
            hint=" Set cookie1 to a classic sweet flavour. Encode with Base64!"
        ))
        return response  # <--- IMPORTANT!



    # Stage 1: cookie1 = chocolate (Base64)
    expected1 = base64.b64encode(b"chocolate").decode()
    if cookie1 != expected1:
        response.set_data(render_template('index.html',
            stage=1,
            message=" Try again! Set cookie1 value to a classic sweet flavour (Base64).",
            hint="Hint: Think of the favorite factory of Charlie"
        ))
        return response
    

    # Stage 2: cookie2 = chip (Base64)
    expected2 = base64.b64encode(b"chip").decode()
    if cookie2 != expected2:
        response.set_data(render_template('index.html',
            stage=2,
            message=" Now something crunchy (cookie2, Base64).",
            hint="Hint: (?)hip. Guess the right letter (?)"
        ))
        return response
    

    # Stage 3: cookie3 = yummy (Base64)
    expected3 = base64.b64encode(b"yummy").decode()
    if cookie3 != expected3:
        response.set_data(render_template('index.html',
            stage=3,
            message=" How do you feel about these cookies? Guess an adjective. (cookie3, Base64)",
            hint="Hint: Starts with y, ends with y"
        ))
        return response
    

    # Final Stage: token = MD5(cookie1 + cookie2 + cookie3 + SECRET)
    correct_token = generate_token("chocolate", "chip", "yummy")
    if token != correct_token:
        response.set_data(render_template('index.html',
            stage=4,
            message="All cookies are correct! What does the current token means??? Then reset a valid token.",
            hint="MD5 of chocolatechipyummy + value of token"
        ))
        return response

    return redirect(url_for('final'))
    
@app.route('/final')
def final():
    user_cookie = request.cookies.get('user')
    signature = request.cookies.get('signature')

    if not user_cookie or not signature:
        res = make_response(render_template('final.html',
            message="<p>You're almost done! Set a 'user' cookie and a matching 'signature' cookie (HMAC-SHA256).</p>" \
            "<p>signature = HMAC(secret, user)</p>"
            "<p>Check Console for hint!</p>",
            hint="The blue box seems weird."
        ))
        return res
    
    expected_signature = generate_signed_cookie(user_cookie)

    if not hmac.compare_digest(signature, expected_signature):
        return render_template('final.html',
            message="Nice try... but the cookie signature doesn't match. 🍪",
            hint="Where is the secret? Rmemeber use SHA256 HMAC in hex form. Not base64!"
        )
    
    return render_template('final.html',
        message="<p>Congratulations! You've completed the challenge! 🎉</p>" \
        "<p>Here is your flag: <strong>cuhk25ctf{1_LuV_Co0k135_X_minT_choc0l@te}</strong></p>",
        hint="Well Done! Player! Keep going!")

if __name__ == '__main__':
    app.run(host = '0.0.0.0', port = 25032, debug=False)
