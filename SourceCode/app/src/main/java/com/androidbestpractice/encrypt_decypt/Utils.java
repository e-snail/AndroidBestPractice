package com.androidbestpractice.encrypt_decypt;

import android.util.Base64;

import java.security.SecureRandom;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by wuyongbo on 2015/10/14.
 */
public class Utils {

    /**
     * AES算法生成SecretKey
     * @param password
     * @param salt 盐是用作加密算法中单向函数输入的一段随机数据
     * @return
     */
    public static SecretKey generateKey(char[] password, byte[] salt) {
        int iterations = 1000;
        int outputKeyLength = 256;

        SecretKeySpec secretKeySpec = null;
        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec keySpec = new PBEKeySpec(password, salt, iterations, outputKeyLength);
            byte[] keyBytes = secretKeyFactory.generateSecret(keySpec).getEncoded();
            secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return secretKeySpec;
    }

    /**
     * 加密算法。加密后的数据可以通过网络传输到服务器，或者保存在本地。
     * 使用正则表达式来检验密码的复杂度？？
     * @param password
     * @param plainText
     * @return
     * @throws Exception
     */
    public static String encryptClearText(char[] password, String plainText) throws Exception{
        SecureRandom secureRandom = new SecureRandom();
        int saltLength = 8;
        byte[] salt = new byte[saltLength];
        secureRandom.nextBytes(salt);   //生成长度为8字节的随机salt
        SecretKey secretKey = generateKey(password, salt);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] initVector = new byte[cipher.getBlockSize()];    //初始化Cipher，让明文加密成字节阵列
        secureRandom.nextBytes(initVector);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initVector);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] cipherData = cipher.doFinal(plainText.getBytes("UTF-8"));
        //使用Base64工具类从这些字节生成一个普通String对象
        return Base64.encodeToString(cipherData, Base64.NO_WRAP | Base64.NO_PADDING) +
                "]" +
                Base64.encodeToString(initVector, Base64.NO_WRAP | Base64.NO_PADDING) +
                "]" +
                Base64.encodeToString(salt, Base64.NO_WRAP | Base64.NO_PADDING) ;
    }

    /**
     * 解密算法。用于解密本地保存的或是网上下载的加密数据。
     * @param password
     * @param encodedData
     * @return
     * @throws Exception
     */
    public static String decryptData(char[] password, String encodedData) throws Exception {
        String[] parts = encodedData.split("]");
        byte[] cipherData = Base64.decode(parts[0], Base64.DEFAULT);
        byte[] initVector = Base64.decode(parts[1], Base64.DEFAULT);
        byte[] salt = Base64.decode(parts[2], Base64.DEFAULT);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParams = new IvParameterSpec(initVector);
        SecretKey secretKey = generateKey(password, salt);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);
        return new String(cipher.doFinal(cipherData), "UTF-8");
    }
}
