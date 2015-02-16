import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Random;
import java.util.zip.CRC32;

/**
 * Created by dolphin on 16.02.15.
 */
public class CryptoBackend {

    public static String cryptoFamily = "AES";
    public static String cryptoAlgorithm = "AES/ECB/PKCS5Padding";
    public static String cryptoProvder = "BC";
    public static String cryptoHash = "SHA-256";

    public static void random(byte[] text) {

        Random generator = new Random();
        generator.nextBytes(text);
    }

    public static byte[] generateMasterKey() {

        byte[] randomPart = new byte[60];
        CryptoBackend.random(randomPart);

        CRC32 crc32 = new CRC32();
        crc32.update(randomPart);
        long checkSum = crc32.getValue();

        ByteBuffer masterKey = ByteBuffer.allocate(64);
        masterKey.put(randomPart);
        masterKey.putInt(60, (int) checkSum);

        return masterKey.array();
    }

    public static boolean verifyUserPassword(byte[] password, byte[] encipheredMasterKey) throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, ShortBufferException, InvalidKeyException {

        byte[] masterKey = CryptoBackend.cryptMasterKey(Cipher.DECRYPT_MODE, password, encipheredMasterKey);

        CRC32 crc32 = new CRC32();
        crc32.update(masterKey, 0, 60);

        boolean isPasswordValid = (int)crc32.getValue() == ByteBuffer.wrap(masterKey).getInt(60);
        CryptoBackend.random(masterKey);

        return isPasswordValid;
    }

    public static byte[] crypt(int mode, byte[] key, byte[] inputText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(CryptoBackend.cryptoAlgorithm);
        cipher.init(mode, new SecretKeySpec(key, CryptoBackend.cryptoFamily));

        byte[] outputText = new byte[cipher.getOutputSize(inputText.length)];
        int encipheredTextLength = cipher.update(inputText, 0, inputText.length, outputText, 0);
        encipheredTextLength += cipher.doFinal(outputText, encipheredTextLength);

        return outputText;
    }

    public static byte[] cryptMasterKey(int mode, byte[] password, byte[] inputMasterKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {

        MessageDigest md = MessageDigest.getInstance(CryptoBackend.cryptoHash);
        byte[] passwordMd = md.digest(password);

        return CryptoBackend.crypt(mode, passwordMd, inputMasterKey);
    }

    public static byte[] userCrypt(int mode, byte[] inputText, byte[] password, byte[] encipheredMasterKey) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {

        byte[] masterKey = CryptoBackend.cryptMasterKey(Cipher.DECRYPT_MODE, password, encipheredMasterKey);
        byte[] outputText = CryptoBackend.crypt(mode, masterKey, inputText);
        CryptoBackend.random(masterKey);

        return outputText;
    }
}
