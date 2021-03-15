import os
import pathlib

import requests

from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests


from flask import Flask, abort, session, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Google Credentials for the app
GOOGLE_CLIENT_ID = "1085284943041-thu1iccc33cg0df1j3ns512g6uehficr.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")



flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/oauth2callback"
)

# to allow http request
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# folder to store imgs
UPLOAD_FOLDER = './static/img'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = "random-secret-key"

# initiate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["5 per minute", "1 per second"],
)

# wrapper for login
def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper


@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


# to be redirected after auth
@app.route("/oauth2callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/upload")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# default route
@app.route("/")
def index():
    return "Hello World <a href='/login'><button>Login</button></a>"


# upload api
@app.route('/upload')
@login_is_required
def upload_file():
   return render_template('upload.html')
	

@app.route('/uploader', methods = ['GET', 'POST'])
@login_is_required
@limiter.limit("5 per minute")
def upload_files():
   if request.method == 'POST':
      f = request.files['file']
      if secure_filename(f.filename) == '':
          return redirect(url_for('upload_file'))
      if not os.path.isdir(UPLOAD_FOLDER):
          os.mkdir(UPLOAD_FOLDER)
      f.save(os.path.join(UPLOAD_FOLDER,secure_filename(f.filename)))
      return f'file uploaded successfully {f.filename}'
		
if __name__ == '__main__':
   app.run(host="0.0.0.0")
