import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class Hidenc {

    //To read the input file
    public static byte[] readFile(String data) {
        try {
            return Files.readAllBytes(Path.of(data));
        } catch (IOException e) {
            System.out.println("Error: The input file cannot be read.");
            System.exit(1);
        } catch (NullPointerException e) {
            System.out.println("Error: There needs to be an argument containing the input file in the form of '--input=INPUT'.");
            System.exit(1);
        }
        return new byte[0];
    }

    //To write to the output file
    public static void writeFile(byte[] data, String name) {
        try {
            Files.write(Path.of(name), data);
            System.exit(0);
        } catch (IOException e) {
            System.out.println("Error: The output file cannot be written.");
            System.exit(1);
        } catch (NullPointerException e) {
            System.out.println("Error: There needs to be an argument containing the output file name in the form of '--output=OUTPUT'.");
            System.exit(1);
        }
    }

    //To get the value of the argument using their "keys"
    public static Map<String, String> mapArguments(String[] args) {
        Map<String, String> arguments = new HashMap<>();

        for (String arg : args) {
            String[] split = arg.split("=");
            if (split.length != 2) {
                System.out.println("Error: Invalid argument : " + Arrays.toString(split));
                System.exit(1);
            }
            arguments.put(split[0], split[1]);
        }
        return arguments;
    }

    //To turn the hex String into a byte array
    public static byte[] hexStringToByteArray(String s) {
        if (s == null) {
            System.out.println("Error: There needs to be an argument containing the key in the form of '--key=KEY'.");
            System.exit(1);
        }
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    //To create message digest / hashed value
    public static byte[] createHash(byte[] byteArray) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error: Algorithm is not available");
            System.exit(1);
        }
        return md.digest(byteArray);
    }

    public static Cipher createCipher(byte[] key, byte[] ctr) {
        Cipher cipher = null;
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            if (ctr != null) { //used for task 4
                IvParameterSpec iv = new IvParameterSpec(ctr);
                cipher = Cipher.getInstance("AES/CTR/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
            } else { //used for task 2
                cipher = Cipher.getInstance("AES/ECB/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException e) {
            System.out.println("Error: Failed to get cipher");
            System.exit(1);
        }
        return cipher;
    }

    //To encrypt
    public static byte[] encrypt(byte[] block) {
        try {
            return cipher.doFinal(block);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Error: Failed to encrypt block");
            System.exit(1);
        }
        return new byte[0];
    }

    //Create and encrypt the Blob (containing the 4 sections in the correct order) in the form of array of bytes
    public static byte[] createEncryptedBlob(byte[] data, byte[] hashedKey, byte[] hashedData) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(data.length + hashedKey.length * 2 + hashedData.length);
        byteBuffer.put(hashedKey);
        byteBuffer.put(data);
        byteBuffer.put(hashedKey);
        byteBuffer.put(hashedData);
        return encrypt(byteBuffer.array());
    }

    //Create the Container (containing offset, blob and padding in the correct order) in the form of array of bytes
    public static byte[] createContainer(int offset, byte[] encryptedBlob, int size) {
        //the container is as big as the size
        ByteBuffer container = ByteBuffer.allocate(size);

        //the offset part of the container is filled with random
        byte[] offsetBytes = new byte[offset];
        new SecureRandom().nextBytes(offsetBytes);

        //the rest of teh container (after blob) is filled with random
        byte[] rest = new byte[size - offset - encryptedBlob.length];
        new SecureRandom().nextBytes(rest);

        container.put(offsetBytes);
        container.put(encryptedBlob);
        container.put(rest);
        return container.array();
    }

    //Generating random offset (if it's not given)
    private static int generateOffset(int size, int blobLen) {
        //offset < size - blob's Len
        Random rnd = new Random();
        int number = rnd.nextInt(size - blobLen - 16) + 16;
        int r = number % 16;
        return number - r;
    }

    public static Cipher cipher;

    public static void main(String[] args) {
        Map<String, String> arguments = mapArguments(args);
        byte[] data = readFile(arguments.get("--input"));
        byte[] key = hexStringToByteArray(arguments.get("--key"));
        byte[] hashedKey = createHash(key);
        byte[] hashedData = createHash(data);


        byte[] ctr = null;
        if (arguments.containsKey("--ctr")) {
            ctr = hexStringToByteArray(arguments.get("--ctr"));
        }

        byte[] template = null;
        int size = -1;
        if (arguments.containsKey("--template")) {
            template = readFile(arguments.get("--template"));
            size = template.length;
        } else if (arguments.containsKey("--size")) {
            size = Integer.parseInt(arguments.get("--size"));
        } else {
            size = 2048;
        }

        cipher = createCipher(key, ctr);

        //create the encrypted blob
        byte[] encryptedBlob = createEncryptedBlob(data, hashedKey, hashedData);

        //set the offset (given or generated)
        int offset;
        if (!arguments.containsKey("--offset")) {
            offset = generateOffset(size, encryptedBlob.length);
        } else {
            offset = Integer.parseInt(arguments.get("--offset"));
        }

        //for the case that both offset and the size (either directly or by template) are given and teh numbers aren't suitable
        if (offset + encryptedBlob.length > size) {
            System.out.println("Error: The container's size is smaller than Blob's size and the offset.");
            System.exit(1);
        }

        byte[] container;
        if (template == null) {
            container = createContainer(offset, encryptedBlob, size);
        } else {
            System.arraycopy(encryptedBlob, 0, template, offset, encryptedBlob.length);
            container = template;
        }

        writeFile(container, arguments.get("--output"));
    }

}