from flask import *
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/ecc/enkripsi')
def ecc_enkripsi():
    return render_template("ecc_enkripsi.html")

@app.route('/ecc/dekripsi')
def ecc_dekripsi():
    return render_template("ecc_dekripsi.html")

@app.route('/ecc/genKey')
def ecc_genKey():
    return render_template("ecc_key.html")
    
if __name__ == "__main__":
    app.run(debug=True)