package util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;

public class Utility {
    /**
     * Questa funzione permette di generare una stringa alfanumerica casuale. Per fare ciò è sufficiente
     * specificare la lunghezza della stringa in ingresso, la stringa in uscita conterrà lettere minuscole
     * dalla a alla z, lettere maiuscole dalla A alla Z e caratteri numerici da 0 a 9, non saranno previsti
     * in alcun modo caratteri speciali e lettere accentate di nessun genere.
     * @param lunghezza
     * @return stringa
    */
    public static String generaCodice(int lunghezza){
        String stringaAlfaNumerica = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
        StringBuilder output = new StringBuilder(lunghezza);
        int indice = 0;
        for (int i = 0; i < lunghezza; i++) {
            indice = (int)(stringaAlfaNumerica.length() * Math.random());
            output.append(stringaAlfaNumerica.charAt(indice));
        }
        return output.toString();
    }

    /**
     * Questa funziona prende in ingresso una stringa, la codifica con l'algoritmo RSA2048 e restituisce
     * in uscita la stringa crittografata.
     * @param chiave
     * @return stringaCrittografata
    */
	public static String crittografaChiave(String chiave){
		return chiave;
	}

        /**
     * Questa funzione permette di leggere un file di testo, in particolare, inizia
     * dal nome del file passato in input alla funzione, dopo aver aperto il file
     * corretto, legge le righe una alla volta e le inserisce in un ArrayList di stringhe.
     * Alla fine restituisce l'ArrayList completo in output, in caso di errore restituisce
     * null.
     * @param nomeFile
     * @return righeFile
     */
    public static ArrayList<String> leggiFileTesto(String nomeFile){
        try {
        	ArrayList<String> righe = new ArrayList<>();
        	File file = new File(nomeFile);
            FileReader fileReader = new FileReader(file);
            BufferedReader reader = new BufferedReader(fileReader);
            String riga = reader.readLine();
            while(riga != null){
                righe.add(riga);
                riga = reader.readLine();
            }
            reader.close();
            fileReader.close();
            return righe;
        }catch(IOException e){
            return null;
        }
    }

    /**
     * Quasta funzione è una estensione della funzione leggiFileTesto che restituisce in output
     * un ArrayList. Essa parte dall'ArrayList letto dalla funzione base, per ogni riga del file
     * divide la stringa in due parti individuando il carattere separatore. La funzione restituisce
     * in output un oggetto HashMap in cui ogni elemento è composto da una coppia chiave-valore.
     * Le chiavi corrispondono alla prima parte delle stringhe estratte, il valore corrisponde alla
     * seconda parte delle stringhe.
     * @param nomeFile
     * @param separatore
     * @return righeFile
     */
    public static HashMap<String,String> leggiFileTesto(String nomeFile,String separatore){
        ArrayList<String> righe = leggiFileTesto(nomeFile);
        if(righe == null){
            return null;
        }
        HashMap<String,String> output = new HashMap<>();
        for(String riga:righe){
            String[] chiaveValore = riga.split(separatore);
            output.put(chiaveValore[0],chiaveValore[1]);
        }
        return output;
    }

    /**
     * Questa funzione permette di aprire un file di testo ed aggiungere al
     * suo interno una nuova riga in fondo al file. Essa prende in ingresso
     * due parametri che corrispondono al nome del file e alla stringa da
     * aggiungere. Alla fine se è tutto corretto restituisce true, altrimenti
     * in caso di errore restituisce false.
     * @param nomeFile
     * @param stringa
     * @return {@code true} o {@code false}
     */
    public static boolean scriviTesto(String nomeFile,String stringa){
        try {
            FileWriter fileWriter = new FileWriter(nomeFile, true);
            BufferedWriter writer = new BufferedWriter(fileWriter);
            PrintWriter out = new PrintWriter(writer);
            out.println(stringa);
            out.flush();
            out.close();
            writer.close();
            fileWriter.close();
            return true;
        }catch(IOException e){
            return false;
        }
    }

    /**
     * Questa funzione permette di aprire un file di testo e scrivere al
     * suo interno il contenuto di un ArrayList che prende come parametro di
     * ingresso. Ogni elemento dell'ArrayList corrisponde ad una riga del file.
     * La funzione prende in ingresso due parametri, il primo corrisponde al nome
     * del file, invece, il secondo è quello spiegato sopra. Alla fine se è tutto
     * corretto la funzione restituisce true, altrimenti in caso di errore restituisce
     * false.
     * @param nomeFile
     * @param stringhe
     * @return {@code true} o {@code false}
     */
    public static boolean scriviRighe(String nomeFile,ArrayList<String> stringhe){
        try {
            FileWriter fileWriter = new FileWriter(nomeFile, true);
            BufferedWriter writer = new BufferedWriter(fileWriter);
            PrintWriter out = new PrintWriter(writer);
            for(String stringa:stringhe){
                out.println(stringa);
                out.flush();
            }
            out.close();
            writer.close();
            fileWriter.close();
            return true;
        }catch(IOException e){
            return false;
        }
    }

    /**
     * Questa funzione permette di eliminare una riga da un file di testo. Per
     * svolgere questo compito essa prende in ingresso due parametri che corrispondono
     * al nome del file ed alla riga da eliminare. La funzione, dopo aver aperto
     * il file legge tutte le righe contenute in esso e le confronta con la riga
     * da eliminare, aggiungendo tutte le righe tranne quella da eliminare in un
     * ArrayList. A questo punto, elimina completamente il file di testo e lo ricrea
     * da capo scrivendo al suo interno le righe contenute nell'ArrayList. La funzione
     * restituisce true se tutte le operazioni vanno a buon fine, altrimenti in caso di
     * errore restituisce false.
     * @param nomeFile
     * @param rigaDaEliminare
     * @return {@code true} o {@code false}
     */
    public static boolean eliminaRiga(String nomeFile,String rigaDaEliminare){
        try {
        	File file = new File(nomeFile);
            FileReader fileReader = new FileReader(file);
            BufferedReader reader = new BufferedReader(fileReader);
            ArrayList<String> righe = new ArrayList<>();
            String riga = reader.readLine();
            while(riga != null){
                if(!riga.contains(rigaDaEliminare)){
                    righe.add(riga);
                }
                riga = reader.readLine();
            }
            reader.close();
            fileReader.close();
            if(file.delete()){
                FileWriter fileWriter = new FileWriter(nomeFile, true);
                BufferedWriter writer = new BufferedWriter(fileWriter);
                PrintWriter out = new PrintWriter(writer);
                for(String riga1:righe){
                    out.println(riga1);
                    out.flush();
                }
                out.close();
                writer.close();
                fileWriter.close();
                return true;
            }
            return false;
        }catch(IOException e){
            return false;
        }
    }

    public static boolean eliminaRiga(String nomeFile,int indiceRigaDaEliminare){
        try {
        	File file = new File(nomeFile);
            FileReader fileReader = new FileReader(file);
            BufferedReader reader = new BufferedReader(fileReader);
            ArrayList<String> righe = new ArrayList<>();
            String riga = reader.readLine();
            while(riga != null){
                righe.add(riga);
                riga = reader.readLine();
            }
            reader.close();
            fileReader.close();
            righe.remove(indiceRigaDaEliminare);
            if(file.delete()){
                FileWriter fileWriter = new FileWriter(nomeFile, true);
                BufferedWriter writer = new BufferedWriter(fileWriter);
                PrintWriter out = new PrintWriter(writer);
                for(String riga1:righe){
                    out.println(riga1);
                    out.flush();
                }
                out.close();
                writer.close();
                fileWriter.close();
                return true;
            }
            return false;
        }catch(IOException e){
            return false;
        }
    }
}