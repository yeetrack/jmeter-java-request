package com.yeetrack.jmeter.java;

import java.security.MessageDigest;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

/**
 * 计算摘要的工具类
 * 
 * @author:
 * @since：2011-6-1 下午06:07:38
 * @version:
 * @Company: 美丽说（meilishuo）
 */
public class Digest {

	/**
	 * 使用MD5算法计算摘要，并对结果进行hex转换
	 * 
	 * @param data
	 *            源数据
	 * @return 摘要信息
	 */
	public static String md5DigestToHex(String str) {
		try {
			byte[] data = str
					.getBytes(ConfigureEncryptAndDecrypt.CHAR_ENCODING);
			MessageDigest md = MessageDigest
					.getInstance(ConfigureEncryptAndDecrypt.MD5_ALGORITHM);
			return Hex.encodeHexString(md.digest(data));
		} catch (Exception e) {
			throw new RuntimeException("digest fail!", e);
		}
	}

	/**
	 * 使用MD5算法计算摘要，并对结果进行base64转换
	 * 
	 * @param data
	 *            源数据
	 * @return 摘要信息
	 */
	public static String md5DigestToBase64(String str) {
		try {
			byte[] data = str
					.getBytes(ConfigureEncryptAndDecrypt.CHAR_ENCODING);
			MessageDigest md = MessageDigest
					.getInstance(ConfigureEncryptAndDecrypt.MD5_ALGORITHM);
			return Base64.encodeBase64String(md.digest(data));
		} catch (Exception e) {
			throw new RuntimeException("digest fail!", e);
		}
	}

	/**
	 * 使用SHA-1算法计算摘要，并对结果进行hex转换
	 * 
	 * @param str
	 *            源数据
	 * @return 摘要信息
	 */
	public static String shaDigestToHex(String str) {
		try {
			byte[] data = str
					.getBytes(ConfigureEncryptAndDecrypt.CHAR_ENCODING);
			MessageDigest md = MessageDigest
					.getInstance(ConfigureEncryptAndDecrypt.SHA1_ALGORITHM);
			return Hex.encodeHexString(md.digest(data));
		} catch (Exception e) {
			throw new RuntimeException("digest fail!", e);
		}
	}

	/**
	 * 使用SHA-1算法计算摘要，并对结果进行base64转换
	 * 
	 * @param str
	 *            源数据
	 * @return 摘要信息
	 */
	public static String shaDigestToBase64(String str) {
		try {
			byte[] data = str
					.getBytes(ConfigureEncryptAndDecrypt.CHAR_ENCODING);
			MessageDigest md = MessageDigest
					.getInstance(ConfigureEncryptAndDecrypt.SHA1_ALGORITHM);
			return Base64.encodeBase64String(md.digest(data));
		} catch (Exception e) {
			throw new RuntimeException("digest fail!", e);
		}
	}

	public static byte[] shaDigest(String str) {
		try {
			byte[] data = str
					.getBytes(ConfigureEncryptAndDecrypt.CHAR_ENCODING);
			MessageDigest md = MessageDigest
					.getInstance(ConfigureEncryptAndDecrypt.SHA1_ALGORITHM);
			return md.digest(data);
		} catch (Exception e) {
			throw new RuntimeException("digest fail!", e);
		}
	}

	/**
	 * 根据指定算法计算摘要
	 * 
	 * @param str
	 *            源数据
	 * @param alg
	 *            摘要算法
	 * @param charencoding
	 *            源数据获取字节的编码方式
	 * @return 摘要信息进行Hex编码
	 */
	public static String digestToHex(String str, String alg, String charencoding) {
		try {
			byte[] data = str.getBytes(charencoding);
			MessageDigest md = MessageDigest.getInstance(alg);
			return Hex.encodeHexString(md.digest(data));
		} catch (Exception e) {
			throw new RuntimeException("digest fail!", e);
		}
	}

	/**
	 * 根据指定算法计算摘要
	 * 
	 * @param str
	 *            源数据
	 * @param alg
	 *            摘要算法
	 * @param charencoding
	 *            源数据获取字节的编码方式
	 * @return 摘要信息进行base64编码
	 */
	public static String digestToBase64(String str, String alg,
			String charencoding) {
		try {
			byte[] data = str.getBytes(charencoding);
			MessageDigest md = MessageDigest.getInstance(alg);
			return Hex.encodeHexString(md.digest(data));
		} catch (Exception e) {
			throw new RuntimeException("digest fail!", e);
		}
    }
    

}
