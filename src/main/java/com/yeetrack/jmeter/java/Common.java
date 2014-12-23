package com.yeetrack.jmeter.java;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import sun.misc.BASE64Encoder;

/**
 * Created by Xuemeng Wang on 14-9-18.
 */
public class Common {
    private static final boolean isChinese(char c) {
        Character.UnicodeBlock ub = Character.UnicodeBlock.of(c);
        if (ub == Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS
                || ub == Character.UnicodeBlock.CJK_COMPATIBILITY_IDEOGRAPHS
                || ub == Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS_EXTENSION_A
                || ub == Character.UnicodeBlock.GENERAL_PUNCTUATION
                || ub == Character.UnicodeBlock.CJK_SYMBOLS_AND_PUNCTUATION
                || ub == Character.UnicodeBlock.HALFWIDTH_AND_FULLWIDTH_FORMS) {
            return true;
        }
        return false;
    }

    public static final boolean isChinese(String strName) {
        char[] ch = strName.toCharArray();
        for (int i = 0; i < ch.length; i++) {
            char c = ch[i];
            if (isChinese(c)) {
                return true;
            }
        }
        return false;
    }


    public static String[] get_except(String result) {
        return result.split(",");
    }

    public static String[] get_pay_except(String result) {
        return result.split("\\|");
    }

    public static String createLinkString(Map<String, String> params) {
        List<String> keys = new ArrayList<String>(params.keySet());
        Collections.sort(keys);
        String prestr = "";
        for (int i = 0; i < keys.size(); i++) {
            String key = keys.get(i);
            String value = params.get(key);

            if (i == keys.size() - 1) {
                prestr = prestr + key + "=" + value;
            } else {
                prestr = prestr + key + "=" + value + "&";
            }
        }
        System.out.println(prestr);
        return prestr;
    }

    public static String sign(String text, String key, String input_charset) {
        // logger.debug("MonitorProject=mlsPayCore | MonitorClass=CheckHmacServiceImpl.sign |  text="+text+" , key="+key);
        String text2 = text+key;
        //System.out.println("要加密的串--->"+text2);

        String result = new String(Base64.encodeBase64(Digest.shaDigest(text2)));
        //System.out.println("base64 after--->"+result);
        return result;
    }


    private static byte[] getContentBytes(String content, String charset) {
        if (charset == null || "".equals(charset)) {
            return content.getBytes();
        }
        try {
            return content.getBytes(charset);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("MD5:"
                    + charset);
        }
    }

    private static Map<String, String> getMap(String para) {
        Map<String, String> map = new HashMap<String, String>();
        String[] kv = para.split("&");
        for (int i = 0; i < kv.length; i++) {
            String[] str = kv[i].split("=");
            if (str.length > 1) {
                map.put(kv[i].split("=")[0], kv[i].split("=")[1]);
            } else {
                map.put(kv[i].split("=")[0], "");
            }
        }
        return map;
    }

    public static String getHMAC(String para, String key) {
        String linkString = createLinkString(getMap(para));
        //String key = "953b953831b73d2b635c86108fb36b80";
        String hack = sign(linkString, key, "UTF-8");
        return hack;
    }

    public static String getToday() {
        SimpleDateFormat df = new SimpleDateFormat("yyyyMMddHHmmss");// 设置日期格式
        return df.format(new Date());// new Date()为获取当前系统时间
    }

    public static String getTomorrow() {
        SimpleDateFormat df = new SimpleDateFormat("yyyyMMddHHmmss");// 设置日期格式
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, +1);    //得到后一天
        Date date = calendar.getTime();
        return df.format(date);
    }

//    public static String get3Des(String plain, String key)
//    {
//        System.out.println("start 3des");
//        byte[] bytes = DESede.encrypt(plain.getBytes(), key.getBytes());
//        String result = new String(Base64.encodeBase64(bytes));
//        System.out.println("!!!!!!!!!-->"+result);
//        return result;
//    }

    public static void main(String[] args) {
        String s = "bankCode=CMB&bgRetUrl=http://dootalab.meilishuo.com/2.0/mpay/mpay_notify&browserType=WAP&busiTypeId=DOOTA&curId=CNY&merchantId=MLS_I_00000001&orderAmount=0.01&orderDate=20141204142958&orderNo=642170PAYTEST&pageRetUrl=http://newlab.meilishuo.com/&pmCode=DCARD&productName=123&shareData=[{\"merchantCode\":\"MLS_D_00090001\",\"amount\":\"0.01\",\"freight\":\"0.00\",\"coupon\":\"0.00\",\"orderId\":\"\"}]&transTypeId=DANBAO&validityDate=20141205142958&version=20131111";
        System.out.println(s);
        String str = getHMAC(s, "key");
        System.out.println(str);
    }
}
