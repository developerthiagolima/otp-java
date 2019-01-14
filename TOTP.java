import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;

public class TOTP {

	private static final int[] DIGITS_POWER
	= { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };
	
	private static final String CRYPTO = "HmacSHA1";
    private static final String keyTOTP = "senha";
    private static final int DIGITS = 6;

	TOTP() {
	}

	private static byte[] hmacSha(byte[] keyBytes, byte[] text) {
		try {
			Mac hmac;
			hmac = Mac.getInstance(CRYPTO);
			SecretKeySpec macKey = new SecretKeySpec(keyBytes, CRYPTO);
			hmac.init(macKey);
			return hmac.doFinal(text);
		} catch (GeneralSecurityException gse) {
			throw new UndeclaredThrowableException(gse);
		}
	}
	
	public static int generateTOTP() {
		byte[] data = new byte[8];
        long value = getCurrentInterval();
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }
        
		byte[] hash = hmacSha(new Base32().decode(keyTOTP.toUpperCase()), data);

		int offset = hash[hash.length - 1] & 0xf;

		int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
				| ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
		
		int otp = binary % DIGITS_POWER[DIGITS]; 

		return otp;
	}
	
	private static long getCurrentInterval() {
		long currentTimeSeconds = System.currentTimeMillis() / 1000;
		return currentTimeSeconds / 30;
	}
	
}
