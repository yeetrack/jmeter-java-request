package com.yeetrack.jmeter.java; /**
 * @Copyright: Copyright (c)2014
 * @Company: 美丽说（meilishuo） 
 */

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;


/**
 * 3des加解密算法工具类
 * 
 * 2014-12-10
 * 3DES
 * 计算模式及补位方式更换为：DESede/CBC/PKCS5Padding
 * 
 * @author:
 * @since：2011-6-1 下午07:52:58
 * @version:
 */
public class DESede {
	
		private final static String IV = "12345678";
	
	/**
	 * 字符串 DESede(3DES) 加密
	 * 
	 * @param key
	 *            - 为24字节的密钥（3组x8字节）
	 * @param data
	 *            - 需要进行加密的数据（8字节）
	 * @return
	 */
	public static byte[] encrypt(byte[] data, byte[] key) {
		//CheckUtils.notEmpty(data, "data");
		//CheckUtils.notEmpty(key, "key");

		try {
			SecretKey deskey = new SecretKeySpec(key,
					ConfigureEncryptAndDecrypt.DES_ALGORITHM);
			// Cipher c1 = Cipher
			// .getInstance(ConfigureEncryptAndDecrypt.DES_ALGORITHM);
			// Cipher c1 = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			Cipher c1 = Cipher.getInstance("DESede/CBC/PKCS5Padding");
			// c1.init(Cipher.ENCRYPT_MODE, deskey);
			IvParameterSpec ips = new IvParameterSpec(IV.getBytes());
			c1.init(Cipher.ENCRYPT_MODE, deskey, ips);

			return c1.doFinal(data);
		} catch (Exception e) {
			System.out.println("errr");
			System.out.println(e.getMessage());
			throw new RuntimeException("encrypt fail!", e);
		}
	}

	/**
	 * 字符串 DESede(3DES) 解密
	 * 
	 * @param key
	 *            - 为24字节的密钥（3组x8字节）
	 * @param data
	 *            - 需要进行解密的数据（8字节）
	 * @return
	 */
	public static byte[] decrypt(byte[] data, byte[] key) {
		//CheckUtils.notEmpty(data, "data");
		//CheckUtils.notEmpty(key, "key");
		if (key.length != 24) {
			throw new RuntimeException(
					"Invalid DESede key length (must be 24 bytes)");
		}
		try {
			SecretKey deskey = new SecretKeySpec(key,
					ConfigureEncryptAndDecrypt.DES_ALGORITHM);
			// Cipher c1 = Cipher
			// .getInstance(ConfigureEncryptAndDecrypt.DES_ALGORITHM);
			Cipher c1 = Cipher.getInstance("DESede/CBC/PKCS5Padding");
			// c1.init(Cipher.DECRYPT_MODE, deskey);
			IvParameterSpec ips = new IvParameterSpec(IV.getBytes());
			c1.init(Cipher.DECRYPT_MODE, deskey, ips);
			return c1.doFinal(data);
		} catch (Exception e) {
			throw new RuntimeException("decrypt fail!", e);
		}
	}

	/**
	 * 加密并对加密结果进行base64编码
	 * 
	 * @param key
	 * @param data
	 * @return
	 */
	public static String encryptToBase64(String data, String key) {
		try {
			byte[] keyByte = key
					.getBytes(ConfigureEncryptAndDecrypt.CHAR_ENCODING);
			byte[] dataByte = data
					.getBytes(ConfigureEncryptAndDecrypt.CHAR_ENCODING);
			byte[] valueByte = encrypt(dataByte, keyByte);
			return Base64.encodeBase64String(valueByte);
		} catch (Exception e) {
			throw new RuntimeException("encrypt fail!", e);
		}
	}

	/**
	 * 先进行base64解码，再进行3des解密
	 * 
	 * @param key
	 * @return
	 */
	public static String decryptFromBase64(String data, String key) {
		try {
			byte[] keyByte = key
					.getBytes(ConfigureEncryptAndDecrypt.CHAR_ENCODING);
			byte[] valueByte = Base64.decodeBase64(data.getBytes());
			byte[] dataByte = decrypt(valueByte, keyByte);
			String str = new String(dataByte,
					ConfigureEncryptAndDecrypt.CHAR_ENCODING);
			return str;
		} catch (Exception e) {
			throw new RuntimeException("decrypt fail!", e);
		}
	}
}