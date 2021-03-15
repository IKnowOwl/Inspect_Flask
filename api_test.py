import os
from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

UPLOAD_FOLDER = './static/img'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["5 per minute", "1 per second"],
)

@app.route('/upload')
def upload_file():
   return render_template('upload.html')
	

@app.route('/uploader', methods = ['GET', 'POST'])
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
   app.run(debug = True,host="0.0.0.0")
