def pbb(a,b):
    if(b==0):
        return a
    else:
        return pbb(b,a%b)

def is_prima(n):
    found = 0
    if(n > 1):
        for i in range(2, int(n**0.5) + 1):
            if (n % i == 0):
                found = 1
                break
        if (found == 0):
            return True
        else:
            return False
    else:
        return False

def kpk(a,b):
    return int((a / pbb(a,b)) * b)

def getKunci(p, q, g):
    if((pbb(p*q, (p-1)*(q-1)) == 1) \
        and (p != q) \
        and (p*q > 255)\
        and (is_prima(p))\
        and (is_prima(q))):
        n = p*q
        lamda = kpk(p-1, q-1)
        if(g < n**2):
            #Masuk ke rumus
            L_xnya = L_x(g, lamda, n)
            miunya = modulo_inverse(L_xnya, n)
            if(miunya != -1):
                return(g,n,lamda,miunya)
            else:
                return("Maaf, pilih angka g yang lebih besar")
        else:
            return ("Maaf, pilih angka g yang lebih kecil dari " + str(n**2))
    else:
        return ("Maaf, pilih bilangan prima yang lain atau lebih p x q lebih besar dari 255")

def enkripsi_huruf(m, r, g, n):
    return int(((g**m)%(n**2)) * ((r**n)%(n**2)) % (n**2))

def enkripsi(pesan, r, g, n):
    if((r < 0 and r >= n) or (pbb(r, n)!=1)):
        return -1
    else:
        hasil = ""
        for huruf in pesan:
            hasil += str(enkripsi_huruf(ord(huruf), r, g, n))
            hasil += " "
        return hasil

def dekripsi_huruf(c, lamda, miu, n):
    return((L_x(c, lamda, n) * miu) % n)

def dekripsi(cipher, lamda, miu, n):
    hasil = ""
    pesan = cipher.split()
    for angka in pesan:
        angkanya = dekripsi_huruf(int(angka), lamda, miu, n)
        hasil += chr(angkanya)
    return hasil

def L_x(g, lamda, n):
    var = (g**lamda) % (n**2)
    return (int((var-1)/n))

def modulo_inverse(m, n):
    pengali = 1
    while (pengali < n):
        if (((m % n) * (pengali % n)) % n == 1):
            return pengali
        pengali += 1
    return -1

if __name__ == "__main__":
    p = 283
    q = 373
    g = 5652
    #print("pangkat", (5652**30.0) % (77**2))
    print(getKunci(p,q,g))
    pesannya = "saya mau makan"
    #print("pesannya:",pesannya)
    ciphernya = enkripsi(pesannya, 25, getKunci(p,q,g)[0], getKunci(p,q,g)[1])
    #print("enkripsi:", ciphernya)
    plainnya = dekripsi(ciphernya, getKunci(p,q,g)[2], getKunci(p,q,g)[3], getKunci(p,q,g)[1])
    print("dekripsi:", plainnya)