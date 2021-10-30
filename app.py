from flask import *
from src import paillier
import json
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

@app.route('/paillier/enkripsi', methods=["POST"])
def paillier_enkripsi_post():
    if (request.method == 'POST'):
        plain = str(request.form.get("plain"))
        angka_r = int(request.form.get("angka_r"))
        angka_g = int(request.form.get("angka_g"))
        angka_n = int(request.form.get("angka_n"))
        response = paillier.enkripsi(plain, angka_r, angka_g, angka_n)
        if(response == -1 or (angka_r < 0) or (angka_r >= angka_n)):
            hasil = "Maaf, pilih angka r yang lain di antara 0 hingga "+ str(angka_n)
            return render_template("paillier_enkripsi.html",\
                encrypt=False\
                , hasil=hasil)
        else:
             return render_template("paillier_enkripsi.html",\
                encrypt=True\
                , hasil=response)

@app.route('/paillier/dekripsi')
def paillier_dekripsi():
    return render_template("paillier_dekripsi.html")

@app.route('/paillier/dekripsi', methods=["POST"])
def paillier_dekripsi_post():
    if (request.method == 'POST'):
        cipher = str(request.form.get("cipher"))
        angka_lamda = int(request.form.get("angka_lamda"))
        angka_miu = int(request.form.get("angka_miu"))
        angka_n = int(request.form.get("angka_n"))
        response = paillier.dekripsi(cipher, angka_lamda, angka_miu, angka_n)
        return render_template("paillier_dekripsi.html",\
                encrypt=True\
                , hasil=response)

@app.route('/paillier/genKey')
def paillier_genKey():
    return render_template("paillier_key.html")

@app.route('/paillier/genKey', methods=["POST"])
def paillier_genKey_post():
    if (request.method == 'POST'):
        angka_p = int(request.form.get("angka_p"))
        angka_q = int(request.form.get("angka_q"))
        angka_g = int(request.form.get("angka_g"))
        response = paillier.getKunci(angka_p, angka_q, angka_g)
        #print("panjang respons", len(response))
        if(len(response)==4):
            print(str(str(response[0])+" "+str(response[1])))
            return render_template("paillier_key.html", \
                encrypt=True, \
                kunci_public=str(str(response[0])+" "+str(response[1])),\
                kunci_private=str(str(response[2])+" "+str(response[3])))
        else:
            return render_template("paillier_key.html", encrypt=False, \
                hasil=response)
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