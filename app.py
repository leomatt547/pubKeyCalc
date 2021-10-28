from flask import *
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route('/')
def home():
    return render_template("index.html")

#Paillier
@app.route('/paillier/enkripsi')
def paillier_enkripsi():
    return render_template("paillier_enkripsi.html")

@app.route('/paillier/dekripsi')
def paillier_dekripsi():
    return render_template("paillier_dekripsi.html")

@app.route('/paillier/genKey')
def paillier_genKey():
    return render_template("paillier_key.html")

#ECC
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