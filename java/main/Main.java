package main;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;

import util.RsaEncryptionOaepSha256;
import util.Utility;

public class Main{
    public static void main(String[] args) {
        String masterkey = Utility.generaCodice(2^20);
        //String masterkey1 = Utility.crittografaChiave(masterkey);
        PrivateKey key = null;
        try {
            key = RsaEncryptionOaepSha256.getPrivateKeyFromString(masterkey);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        System.out.println(key);
    }
}