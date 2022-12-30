import os
import gc
import Crypto
import random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import hashlib
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
        NBS = (FS-(T<<12))/(T-1)
    print("NBS = ", NBS)
    gc.collect()
    return NBS

#str(base64UrlEncode(bytes(str(hex(int(full_bit_or,2))), encoding='utf-8')).decode('utf-8'))

def calc_offsets(if_name):
    if_name = if_name.split(".")[-2]
    print(if_name) #MHg2MTFkYTkwMjk0NDlkZGFiZmZmYmZjZWZmYmY3ZjliZQ
    R = base64UrlDecode(if_name)[16:]
    R1 = int(R[:8],16)
    R2 = int(R[8:],16)
    SP1 = R1%0x900000
    SP2 = R2%0x9FFC00
    return (SP1, SP2)


def mkey_recover(infected,original):
    print(type(infected),type(original))
    print(infected)
    print(original)
    for k in range(len(infected)):
        i_file = infected[k]
        o_file = original[k]
        NBS = NBS_size_calc(os.stat(i_file).st_size)
        SP1, SP2 = calc_offsets(i_file)
        iter = os.stat(i_file).st_size/(0x1000+NBS)
        offset=0

        EQS = set({None})

        for i in range(0,iter):
            if (i==iter):
                offset = None #final encryption block offset

            for j in range(0,0xFFF):
                O1 = offset%0x100000
                O2 = offset%0x1000
                EQS.add((SP1+O1, SP2+O2, i_file[offset]^o_file[offset]))
                #.IF[offset]^ OF[offset] == byte of EKS
                offset+=1

            offset+=NBS
    # Extract equation end
    EK = [None]*0xA00000
    E = random.choice(tuple(EQS))
    EK[E[0]] = random.choice(tuple(range(256)))
    EQS = tuple(EQS)
    length = len(EQS)
    while len(EQS) == length:
        for EQ in EQS:
            if (EK[EQ[0]] == None) and (EK[EQ[1]] == None):
                pass
            elif (EK[EQ[0]] != None) and (EK[EQ[1]] == None):
                EK[EQ[1]] = EK[EQ[0]] ^ EK[EQ[2]]
            elif (EK[EQ[0]] == None) and (EK[EQ[1]] != None):
                EK[EQ[0]] = EK[EQ[1]] ^ EK[EQ[2]]
            elif (EK[EQ[0]] != None) and (EK[EQ[1]] != None):
                EQS.remove(EQ)
    print(EQS)

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