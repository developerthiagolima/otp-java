import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class AES {

	private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
	private static final String KEY_ALGORITHM = "AES";
	private static final String KEY = "senha";

	public static String encrypt(String plainText) throws Exception {
		byte [] salt = new byte [8];
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(salt);
		
		byte [] keyAndIV = deriveKeyAndIV(KEY.getBytes(), salt);
		byte [] key = Arrays.copyOfRange(keyAndIV, 0, 32);
		byte [] iv = Arrays.copyOfRange(keyAndIV, 32, 48);
		SecretKeySpec skeySpec = new SecretKeySpec(key, KEY_ALGORITHM);
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		
		Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivspec);
		byte [] encrypted = cipher.doFinal(plainText.getBytes());
		
		byte [] to_encode = new byte[ 16 + encrypted.length ];
		System.arraycopy("Salted__".getBytes(), 0, to_encode, 0, 8);
		System.arraycopy(salt, 0, to_encode, 8, 8);
		System.arraycopy(encrypted, 0, to_encode, 16, encrypted.length);
		
		return Base64.encodeBase64String(to_encode);
	}

	public static String decrypt(String encryptedText) throws Exception {
		byte[] decoded = Base64.decodeBase64(encryptedText);
        byte[] salt = Arrays.copyOfRange(decoded, 8, 16);
        byte[] encrypted = Arrays.copyOfRange(decoded, 16, decoded.length);
        
        byte[] keyAndIV = deriveKeyAndIV(KEY.getBytes(), salt);
        byte[] key = Arrays.copyOfRange(keyAndIV, 0, 32);
        byte[] iv = Arrays.copyOfRange(keyAndIV, 32, 48);
		
        SecretKeySpec skeySpec = new SecretKeySpec(key, KEY_ALGORITHM);
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        Cipher cipher;
        cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivspec);
        return new String(cipher.doFinal(encrypted));
	}

	static byte[] deriveKeyAndIV(byte[] password, byte[] salt) throws DigestException, NoSuchAlgorithmException {
		byte[] res = new byte[48];

		final MessageDigest md5 = MessageDigest.getInstance("MD5");

		md5.update(password);
		md5.update(salt);
		byte[] hash1 = md5.digest();

		md5.reset();
		md5.update(hash1);
		md5.update(password);
		md5.update(salt);
		byte[] hash2 = md5.digest();

		md5.reset();
		md5.update(hash2);
		md5.update(password);
		md5.update(salt);
		byte[] hash3 = md5.digest();

		// copy the 3 hashes in the result array
		System.arraycopy(hash1, 0, res, 0, 16);
		System.arraycopy(hash2, 0, res, 16, 16);
		System.arraycopy(hash3, 0, res, 32, 16);
		return res;
	}
}
