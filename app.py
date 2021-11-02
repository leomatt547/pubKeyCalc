from flask import *
from src import paillier,elgamal
from src.rsa import RSA
from src.ecc import ECC
import json
import os

# initialize rsa & ecc
rsa = RSA()
ecc = ECC(9, 7, 2011) # kurva elliptik pilihan

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route('/')
def home():
    return render_template("index.html")

#ElGamal
@app.route('/elgamal/enkripsi')
def elgamal_enkripsi():
    return render_template("elgamal_enkripsi.html")

@app.route('/elgamal/enkripsi', methods=["POST"])
def elgamal_enkripsi_post():
    if (request.method == 'POST'):
        plain = str(request.form.get("plain"))
        angka_k = int(request.form.get("angka_k"))
        angka_g = int(request.form.get("angka_g"))
        angka_y = int(request.form.get("angka_y"))
        angka_p = int(request.form.get("angka_p"))
        response = elgamal.enkripsi(plain, angka_k, angka_g, angka_y, angka_p)
        if(response == -1 or (angka_k < 0) or (angka_k >= angka_p)):
            hasil = "Maaf, pilih angka k yang lain di antara 0 hingga "+ str(angka_p)
            return render_template("elgamal_enkripsi.html",\
                encrypt=False\
                , hasil=hasil)
        else:
             return render_template("elgamal_enkripsi.html",\
                encrypt=True\
                , hasil=response)

@app.route('/elgamal/dekripsi')
def elgamal_dekripsi():
    return render_template("elgamal_dekripsi.html")

@app.route('/elgamal/dekripsi', methods=["POST"])
def elgamal_dekripsi_post():
    if (request.method == 'POST'):
        cipher = str(request.form.get("cipher"))
        angka_x = int(request.form.get("angka_x"))
        angka_p = int(request.form.get("angka_p"))
        response = elgamal.dekripsi(cipher, angka_x, angka_p)
        return render_template("elgamal_dekripsi.html",\
                encrypt=True\
                , hasil=response)

@app.route('/elgamal/genKey')
def elgamal_genKey():
    return render_template("elgamal_key.html")

@app.route('/elgamal/genKey', methods=["POST"])
def elgamal_genKey_post():
    if (request.method == 'POST'):
        angka_p = int(request.form.get("angka_p"))
        angka_g = int(request.form.get("angka_g"))
        angka_x = int(request.form.get("angka_x"))
        response = elgamal.getKunci(angka_p, angka_g, angka_x)
        print(len(response))
        if(len(response)==4):
            return render_template("elgamal_key.html", \
                encrypt=True, \
                kunci_public=str(str(response[0])+" "+str(response[1])+" "+str(response[3])),\
                kunci_private=str(str(response[2])+" "+str(response[3])))
        else:
            return render_template("elgamal_key.html", encrypt=False, \
                hasil=response)

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
        angka_x = int(request.form.get("angka_x"))
        angka_p = int(request.form.get("angka_p"))
        angka_n = int(request.form.get("angka_n"))
        response = paillier.dekripsi(cipher, angka_x, angka_p, angka_n)
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
        if(len(response)==4):
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

@app.route('/ecc/enkripsi', methods=["POST"])
def ecc_enkripsi_post():
    if request.method == "POST":
        try:
            plaintext = request.form.get("plain")
            public_key_list = request.form.get("public_key").split()
            if len(public_key_list) != 2:
                raise ValueError
            public_key_list = [int(x) for x in public_key_list]
            for x in public_key_list:
                if x <= 0:
                    raise ValueError
            public_key = tuple(public_key_list) 
            # print(public_key)
            ciphertext = ecc.encrypt(plaintext, public_key) # mungkin perlu handle kalo error
            return render_template("ecc_enkripsi.html", encrypt=True, ciphertext=ciphertext)
        except ValueError:
            message = "Kunci publik harus merupakan pasangan bilangan bulat non-negatif!"
            return render_template("ecc_enkripsi.html", encrypt=False, hasil=message)
    return render_template("ecc_enkripsi.html")

@app.route('/ecc/dekripsi')
def ecc_dekripsi():
    return render_template("ecc_dekripsi.html")

@app.route('/ecc/dekripsi', methods=["POST"])
def ecc_dekripsi_post():
    if request.method == "POST":
        try:
            raw_ciphertext = request.form.get("cipher").split()
            ciphertext = []
            for i in range(0, len(raw_ciphertext), 4):
                ciphertext.append(((int(raw_ciphertext[i]), int(raw_ciphertext[i+1])),\
                    (int(raw_ciphertext[i+2]), int(raw_ciphertext[i+3]))))
            private_key = int(request.form.get("private_key"))
            plaintext = ecc.decrypt(ciphertext, private_key) # mungkin perlu handle kalo error
            return render_template("ecc_dekripsi.html", encrypt=True, hasil=plaintext)
        except (ValueError, IndexError) as e:
            message = "Cipher text harus berisi empat bilangan untuk setiap baris!"
            return render_template("ecc_dekripsi.html", encrypt=False, hasil=message)


@app.route('/ecc/genKey')
def ecc_genKey():
    return render_template("ecc_key.html")
    
@app.route('/ecc/genKey', methods=["POST"])
def ecc_genKey_post():
    if request.method == "POST":
        private_key, public_key = ecc.generate_random_key_pair()
        return render_template("ecc_key.html", private_key=private_key, public_key=public_key)
    return render_template("ecc_key.html")

if __name__ == "__main__":
    app.run(debug=True)