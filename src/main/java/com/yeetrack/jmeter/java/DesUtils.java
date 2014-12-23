package com.yeetrack.jmeter.java;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;

/**
 * Created by Xuemeng Wang on 14-12-23.
 */
public class DesUtils {

    //算法DESede
    private static final String Algorithm = "DESede";

    //工作模式CBC(ECB)，填充模式PKCS5Padding(NoPadding)
    //eg: DESede/CBC/PKCS5Padding, DESede/ECB/PKCS5Padding
    private static final String Transformation = "DESede/CBC/PKCS5Padding";

    //向量iv,ECB不需要向量iv，CBC需要向量iv
    //CBC工作模式下，同样的密钥，同样的明文，使用不同的向量iv加密 会生成不同的密文
    private static final String Iv = "\0\0\0\0\0\0\0\0";

    public static String encryptMode(byte[] keybyte, byte[] src) {
        try {
            // 根据给定的字节数组和算法构造一个密钥
            SecretKey deskey = new SecretKeySpec(keybyte, Algorithm);
            // 加密
            IvParameterSpec iv = new IvParameterSpec(Iv.getBytes());
            Cipher c1 = Cipher.getInstance(Transformation);
            c1.init(Cipher.ENCRYPT_MODE, deskey, iv);
            return byte2hex(c1.doFinal(src));
        } catch (java.security.NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (javax.crypto.NoSuchPaddingException e2) {
            e2.printStackTrace();
        } catch (Exception e3) {
            e3.printStackTrace();
        }
        return null;
    }

    public static String byte2hex(byte[] b) { // 一个字节的数，
        // 转成16进制字符串
        String hs = "";
        String stmp = "";
        for (int n = 0; n < b.length; n++) {
            // 整数转成十六进制表示
            stmp = (Integer.toHexString(b[n] & 0XFF));
            if (stmp.length() == 1)
                hs = hs + "0" + stmp;
            else
                hs = hs + stmp;
        }
        return hs; // 转成大写
    }

    public static String encryptMode(String key, String src) throws UnsupportedEncodingException {
        return encryptMode(getKeyByte(key), src.getBytes());
    }

    private static byte[] getKeyByte(String key) throws UnsupportedEncodingException {
        // 加密数据必须是24位，不足补0；超出24位则只取前面的24数据
        byte[] data = key.getBytes();
        int len = data.length;
        byte[] newdata = new byte[24];
        System.arraycopy(data, 0, newdata, 0, len > 24 ? 24 : len);
        return newdata;
    }

    public static String decryptMode(byte[] keybyte, byte[] src) {
        try {
            // 生成密钥
            SecretKey deskey = new SecretKeySpec(keybyte, Algorithm);
            // 解密
            IvParameterSpec iv = new IvParameterSpec(Iv.getBytes());
            Cipher c1 = Cipher.getInstance(Transformation);
            c1.init(Cipher.DECRYPT_MODE, deskey, iv);
            byte[] data = c1.doFinal(src);
            return new String(data);
        } catch (java.security.NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (javax.crypto.NoSuchPaddingException e2) {
            e2.printStackTrace();
        } catch (Exception e3) {
            e3.printStackTrace();
        }
        return null;
    }

    public static byte[] hex2byte(byte[] b) {
        if ((b.length % 2) != 0)
            throw new IllegalArgumentException("长度不是偶数");
        byte[] b2 = new byte[b.length / 2];
        for (int n = 0; n < b.length; n += 2) {
            String item = new String(b, n, 2);
            // 两位一组，表示一个字节,把这样表示的16进制字符串，还原成一个进制字节
            b2[n / 2] = (byte) Integer.parseInt(item, 16);
        }
        return b2;
    }

    /**
     * @throws java.io.UnsupportedEncodingException
     */
    public static String des(String src, String key) {
        //String key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChDzcjw/rWgFwnxunbKp7/4e8w/UmXx2jk6qEEn69t6N2R1i/LmcyDT1xr/T2AHGOiXNQ5V8W4iCaaeNawi7aJaRhtVx1uOH/2U378fscEESEG8XDqll0GCfB1/TjKI2aitVSzXOtRs8kYgGU78f7VmDNgXIlk3gdhnzh+uoEQywIDAQAB";
        //String src = "01234567890123456789";
        System.out.println("原始数据：" + src);
        String encryptData = null;
        try {
            encryptData = encryptMode(key, src);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        System.out.println("加密数据：" + encryptData);
        String decryptData = null;
        try {
            decryptData = decryptMode(getKeyByte(key), hex2byte(encryptData.getBytes()));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        System.out.println("解密数据：" + decryptData);
        return encryptData;
    }

}
