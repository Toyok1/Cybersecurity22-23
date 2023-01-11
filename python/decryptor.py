import os
import gc
import Crypto
import random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import hashlib
from datetime import datetime
from base64 import urlsafe_b64encode, urlsafe_b64decode

def base64UrlEncode(data):
    return urlsafe_b64encode(data).rstrip(b'=')

def base64UrlDecode(base64Url):
    padding = b'=' * (4 - (len(base64Url) % 4))
    return urlsafe_b64decode(base64Url + str(padding,encoding="utf-8"))


#Calculation of the non-encrypted data block size
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
        NBS = (FS-(int(T)<<12))/(T-1)
    print("NBS = ", NBS)
    gc.collect()
    return int(NBS)

#str(base64UrlEncode(bytes(str(hex(int(full_bit_or,2))), encoding='utf-8')).decode('utf-8'))

def calc_offsets(if_name):
    if_name = if_name.split(".")[-2]
    print(if_name) #MHg2MTFkYTkwMjk0NDlkZGFiZmZmYmZjZWZmYmY3ZjliZQ
    R = if_name.split("_")
    R1 = int(base64UrlDecode(R[1]),16) #int(R[:8],16)
    R2 = int(base64UrlDecode(R[2]),16) #int(R[8:],16)
    SP1 = R1%0x900000
    SP2 = R2%0x9FFC00
    return (SP1, SP2)

def bxor(b1, b2): # use xor for bytes
    result = bytearray()
    for b1, b2 in zip(b1, b2):
        result.append(b1 ^ b2)
    return bytes(result)

def createEQSFile(EQS):
    if os.path.isfile("./EQS.txt"):
        os.remove("EQS.txt")
    with open("EQS.txt",'a') as f:
        f.write("--- EQS created " + str(datetime.now()) + " ---\n\n")
        for EQ in EQS:
            #print(EQ)
            if(EQ is not None):
                f.write(str(EQ[0]) + ", " + str(EQ[1]) + ", " + str(EQ[2]) +"\n")
            else:
                f.write("None\n")

def createEKFile(EK):
    if os.path.isfile("./EK.bin"):
        os.remove("EK.bin")
    with open("EK.bin",'ab') as f:
        #f.write("--- EK created " + str(datetime.now()) + " ---\n\n")
        for E in EK:
            #print(EQ)
            f.write(bytes(E))
            

def mkey_recover(infected,original):
    
    for k in range(len(infected)):
        i_file = infected[k]
        o_file = original[k]
        print(i_file, o_file)
        NBS = NBS_size_calc(os.stat(i_file).st_size)
        SP1, SP2 = calc_offsets(i_file)
        iter = int(os.stat(i_file).st_size/(0x1000+int(NBS)))
        offset=0

        EQS = set({None})
        i_file_file = open(i_file,"rb")
        o_file_file = open(o_file,"rb")
        i_file_opened = i_file_file.read()
        o_file_opened = o_file_file.read()
        i_file_file.close()
        o_file_file.close()
        for i in range(0,iter+1):
            if (i==iter):
                print("ITER")
                if (iter*(0x1000+int(NBS))) - os.stat(i_file).st_size > 0x1000:
                    offset = os.stat(i_file).st_size - 0x1000 #final encryption block offset
                else: 
                    offset = (iter-1) * (0x1000+int(NBS)) + NBS

            for j in range(0,0xFFF):
                O1 = offset%0x100000
                O2 = offset%0x1000
                EQS.add((SP1+O1, SP2+O2, i_file_opened[offset]^o_file_opened[offset])) 
                offset+=1

            offset+=int(NBS)

    
    target = b'\0' #None 

    EK = [target]*0xA00000
    E = random.choice(tuple(EQS))
    EK[E[0]] = random.choice(tuple(range(256)))
    EQS = tuple(EQS)
    #print(EQS.index(None),len(EQS))
    length = len(EQS)

    while len(EQS) == length:
        for EQ in EQS:
            if EQ is None:
                pass
            else:
                if EQ is not None or EQ != (target,target,target) or EQ != (None,):
                    if (EK[EQ[0]] == target) and (EK[EQ[1]] == target):
                        #print("none")
                        pass

                    elif (EK[EQ[0]] != target) and (EK[EQ[1]] == target):
                        print("first", EK[EQ[0]], EK[EQ[1]], EK[EQ[2]])
                        if isinstance(EK[EQ[0]],int):
                            a = EK[EQ[0]].to_bytes(1,"little")
                        else:
                            a = EK[EQ[0]]
                        EK[EQ[1]] =bytes([_a ^ _b for _a, _b in zip(a,EK[EQ[2]])])

                    elif (EK[EQ[0]] == target) and (EK[EQ[1]] != target):
                        #print("second", EK[EQ[0]], EK[EQ[1]], EK[EQ[2]])
                        if isinstance(EK[EQ[1]],int):
                            b = EK[EQ[1]].to_bytes(1,"little")
                        else:
                            b = EK[EQ[1]]
                        EK[EQ[0]] = bytes([_a ^ _b for _a, _b in zip(b,EK[EQ[2]])]) 

                    elif (EK[EQ[0]] != target) and (EK[EQ[1]] != target):
                        print("third", EK[EQ[0]], EK[EQ[1]], EK[EQ[2]])
                        EQS = list(EQS)
                        EQS.remove(EQ)
                        EQS = tuple(EQS)
    createEQSFile(EQS)
    createEKFile(EK)

def create_if_of():
    coll_if = []
    coll_or = []
    if_path = './data'
    or_path = './UNCORRUPTED_DATA'
    if_files = os.listdir(if_path)
    or_files = os.listdir(or_path)

    for if_file in if_files:
        if_file_path = os.path.join(if_path, if_file)
        if os.path.isfile(if_file_path):
            coll_if.append(if_file_path)
    for or_file in or_files:
        or_file_path = os.path.join(or_path, or_file)
        if os.path.isfile(or_file_path):
            coll_or.append(or_file_path)

    return coll_if,coll_or


if __name__ == '__main__':
    IF,OF = create_if_of()
    mkey_recover(IF,OF)