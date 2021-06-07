#----------------------------------------------------------------------------#
# Imports
#----------------------------------------------------------------------------#

from flask import Flask, render_template, request, redirect, url_for, send_file, current_app, jsonify
from werkzeug.utils import secure_filename
from math import floor, log
# from flask.ext.sqlalchemy import SQLAlchemy
import logging
from logging import Formatter, FileHandler
from forms import *
import os
from libs.rsa_algorthm.rsa import generate_key, encrypt_message, SYMBOLS

#----------------------------------------------------------------------------#
# App Config.
#----------------------------------------------------------------------------#

app = Flask(__name__)
app.config.from_object('config')
#db = SQLAlchemy(app)

# Automatically tear down SQLAlchemy.
'''
@app.teardown_request
def shutdown_session(exception=None):
    db_session.remove()
'''

# Login required decorator.
'''
def login_required(test):
    @wraps(test)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return test(*args, **kwargs)
        else:
            flash('You need to login first.')
            return redirect(url_for('login'))
    return wrap
'''
#----------------------------------------------------------------------------#
# Controllers.
#----------------------------------------------------------------------------#


@app.route('/')
def index():
    return render_template('pages/placeholder.home.html')

@app.route('/rsa')
def rsa():
    public_key = request.args.get('public_key') if request.args.get('public_key') != None else ''
    private_key = request.args.get('private_key') if request.args.get('private_key') != None else ''
        
    return render_template('pages/rsa.html', public_key=public_key, private_key=private_key )

@app.route('/rsa', methods=["POST"])
def rsa_post():
    data = request.form.get('button')
    if data == 'Generate':
        pubkey, privkey = generate_key.get_key(1024)

    return  jsonify(
        pubkey = str(pubkey[0]) + ',' + str(pubkey[1]),
        privkey = str(privkey[0]) + ',' + str(privkey[1]),
    )

@app.route('/rsa-encrypt', methods=["POST"])
def rsa_encrypt():
    plaintText = request.form.get('plaintText')
    key = request.form.get('key')
    keysize, n, EorD = key.split(",")
    k1, n1, e1 = (int(keysize), int(n), int(EorD))
    
    blocksize = floor(log(2**k1, len(SYMBOLS)))

    cipher_block = encrypt_message(plaintText, (n1, e1), blocksize)  
    for i in range(len(cipher_block)):
        cipher_block[i] = str(cipher_block[i])

    cipher = ",".join(cipher_block)
    cipher = str(len(plaintText)) + "_" + str(blocksize) + "_" + str(cipher)

    return  jsonify(
        cipher = cipher
    )


@app.route('/generate', methods=['POST'])
def generate():
    
    if request.form['button'] == "Download public key":
        key = request.form['pubkey'].split(',')
        filename = "keys/pubkey.pub"
        name_file = "pubkey"
    
    if request.form['button'] == 'Download private key':
        key = request.form['privkey'].split(',')
        filename = "keys/privkey.pri"
        name_file = "privkey"
    
    print(key)
    file_ = open(filename, 'w')
    file_.write("%s,%s,%s"%(1024, key[0], key[1]))
    file_.close()
    
    return send_file(filename, as_attachment=True)

@app.route('/upload_key', methods=['POST'])
def upload_key(): 
    file = request.files['file']
    filename = secure_filename(file.filename)
    file.save(os.path.join('temp', 'keys.txt'))
    f = open("temp/keys.txt", "r")
    return jsonify(
        text = f.read()
    )

@app.route('/elgamal')
def elgamal():
    return render_template('pages/elgamal.html')

@app.errorhandler(500)
def internal_error(error):
    #db_session.rollback()
    return render_template('errors/500.html'), 500


@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

if not app.debug:
    file_handler = FileHandler('error.log')
    file_handler.setFormatter(
        Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
    )
    app.logger.setLevel(logging.INFO)
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.info('errors')

#----------------------------------------------------------------------------#
# Launch.
#----------------------------------------------------------------------------#

# Default port:
if __name__ == '__main__':
    app.run()

# Or specify port manually:
'''
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
'''
