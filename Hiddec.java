
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.io.*;
import java.security.*;
import java.util.Arrays;

public class Hiddec {
    static Cipher cipher;
    static byte[] key = null; 
    static byte[] ctr = null; 
    static byte[] input = null;
    static String output = null;
    static byte[] digest;
    static byte[] hk;

  public void Arguments(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException  {
        
    for (String argument: args) {
            String[] split = argument.split("=");
           
            switch (split[0]) {
                case "--key":
                    key = hexToByteArray(split[1]);
                    break;

                case "--input":
                    input = readfile(split[1]);
                    break;

                case "--output":
                    output = split[1];
                    break;
                
                case "--ctr":
                    ctr = hexToByteArray(split[1]);
                    break;
               
                    default:
                    System.out.println("Error, Wrong argument!");
                    return;
            }

            if (split.length != 2) {
                System.out.println("Error, Wrong argument length"); 
                System.exit(1);
            }

        }

        if (key == null|| input == null || output == null) {
            System.out.println("Three arguments key, input, output at least needed ");
            System.exit(1);
        }

    }

   
     // Reads the input file 
    public byte[] readfile(String input) throws IOException {
        
        File file = new File(input);
        byte[] byteArray = new byte[(int)file.length()];
        FileInputStream inputStream = null;
        try {
            inputStream = new FileInputStream(file); 
            inputStream.read(byteArray);
        }   
        
        catch(FileNotFoundException e){ 
            System.out.println("File does not found "); 
            System.exit(1);
        }
        
        catch (IOException e) {
            System.out.println("File can not be read ");
            System.exit(1);
        }
     
        inputStream.close();
        return byteArray;

    }

    
    // Write to the output file 
    public void writeFi(byte[] data, String output) throws IOException {
       
        FileOutputStream outputStream = null;
        try { 
            outputStream = new FileOutputStream(output);
            outputStream.write(data);
        }
        catch (IOException e) {
            System.out.println("Can not write in the file");
        }
       
        outputStream.close();
    }


   // Converts a hexadecimal string to a byte array.
    public byte[] hexToByteArray(String key){
 
    byte[] hexByteArray = new byte[key.length() / 2];
   
    try { for (int i = 0; i < hexByteArray.length; i++) {
            int index = i * 2;
            
            // Using parseInt() method of Integer class
          int val = Integer.parseInt(key.substring(index, index + 2), 16);
          hexByteArray[i] = (byte)val;
      }
    }
    catch(NumberFormatException ex){  
        System.err.println("Invalid string in argumment");  
         
    }
    return hexByteArray;
    }
    
   
   

        //MD5 hash
        public byte[] Digest(byte[] inputText){
      
            try {
                MessageDigest md = MessageDigest.getInstance("MD5");
                md.update(inputText);
                digest = md.digest();
           
            } catch (NoSuchAlgorithmException e) {
                System.out.println("Algorithm is not available");
                System.exit(1);
            } catch (Exception e) {
                System.out.println("Exception "+e);
                System.exit(1);
            }
            return digest;
        }



    //Initializes Cipher
      public void Initialize(byte[] ctr, byte[] key) {
        SecretKeySpec CiKey = new SecretKeySpec(key, "AES");  
    try{  
      
        if(ctr == null){
            cipher = Cipher.getInstance("AES/ECB/NoPadding");  
            cipher.init(Cipher.DECRYPT_MODE, CiKey);
        }

        else {
            IvParameterSpec IvPaSp = new IvParameterSpec(ctr);
            cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, CiKey, IvPaSp);
        }
    }
    catch (Exception e) {
        System.out.println(e);
        System.exit(1);
    }
    }




    public byte [] ECB(){
        Initialize(null, key);
        int index = index(input, 0);
        int endIndex = index(input, index + 16);

        if(index == -1 || endIndex == -1){
            System.out.println("Error in data, key is wrong??");
            System.exit(1);
        }

        //extract data 
        byte[] data = Arrays.copyOfRange(input, index + 16, endIndex);
        data = cipher.update(data);
        byte[] hash = Arrays.copyOfRange(input, endIndex + 16, endIndex + 32);
        hash = cipher.update(hash);

        if(CompareByteArrays(Digest(data), hash))
            return data;
        else{
            System.out.println("Wrong data");
            return null;
        }
}


    public byte [] CTR(){
    
        int StIndex = firstCTR(key, input, 0, ctr);
        int EnIndex = index(input, StIndex + 16);

    if(StIndex == -1 || EnIndex == -1){
        System.out.println("Error!");
        System.exit(1);
    }

    //extract data 
    Initialize(ctr, key);
    byte [] i =Arrays.copyOfRange(input, StIndex, StIndex + 16);
    i = cipher.update(i);
    byte [] data = Arrays.copyOfRange(input, StIndex + 16, EnIndex);
    data  = cipher.update(data);
    
    byte[] d = Arrays.copyOfRange(input, EnIndex, EnIndex + 16);
    d = cipher.update(d);
    byte[] hash = Arrays.copyOfRange(input, EnIndex + 16, EnIndex + 32);
    hash = cipher.update(hash);

    if(CompareByteArrays(Digest(data), hash))
        return data;
    else{
        System.out.println("Wrong data");
        return null;
    }
}


    //find the first and last H(k)
    int index(byte[] array, int startIndex){
        int index = startIndex;

        while(array.length > index){    
            byte [] info = Arrays.copyOfRange(array, index, index + 16);
            info = cipher.update(info);

            if(CompareByteArrays(info, hk))
                return index;

            index += 16;    
        }
        return -1;
    }

   //compare
    public boolean CompareByteArrays(byte[] array1, byte[] array2){

        for (int i = 0; i < array1.length; i++){
            if(array1[i] != array2[i]){
                return false;
            }    
        }
        return true;
    }

   //for CTR mode => find first H(k)
    public int firstCTR(byte[] key, byte[] array, int startIndex, byte[] ctr){
        int index = startIndex;
         
        while(array.length > index){
            Initialize(ctr, key);
            byte [] in = Arrays.copyOfRange(array, index, index + 16);
            in = cipher.update(in);

            if(CompareByteArrays(in, hk))
                return index;

            index += 16;
            
        }
        return -1;
    }


    public static void main(String args[]) throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        
        Hiddec hiddec = new Hiddec();
        if(args.length == 3 || args.length == 4){    
              hiddec.Arguments(args); 
    }
        else {
            System.out.println("Needs 3 or 4 arguments: inputfile, outputfile, key, (ctr) ");
            System.exit(1);
        }

        hiddec.hk = hiddec.Digest(key);

        if(ctr == null) {
            byte [] dataE = hiddec.ECB();
            hiddec.writeFi(dataE, output);
        } 
        else if (ctr != null){
            byte [] dataC = hiddec.CTR();
            hiddec.writeFi(dataC, output);
        }

    }
}


