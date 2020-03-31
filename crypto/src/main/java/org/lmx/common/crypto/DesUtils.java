package org.lmx.common.crypto;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.symmetric.SymmetricCrypto;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * 功能描述：基于Cipher实现的DES加解密工具类
 * <pre>
 *     DES是Data Encryption Standard（数据加密标准）的缩写。它是由IBM公司研制的一种对称密码算法，
 *  美国国家标准局于1977年公布把它作为非机要部门使用的数据加密标准，三十年来，
 *  它一直活跃在国际保密通信的舞台上，扮演了十分重要的角色。
 *
 *     DES是一个分组加密算法，典型的DES以64位为分组对数据加密，加密和解密用的是同一个算法。
 *  它的密钥长度是56位（因为每个第8 位都用作奇偶校验），密钥可以是任意的56位的数，而且可以任意时候改变。
 *  其中有极少数被认为是易破解的弱密钥，但是很容易避开它们不用。所以保密性依赖于密钥
 *
 * </pre>
 *
 * @program: block-chain-j
 * @author: LM.X
 * @create: 2020-03-31 09:32
 **/
@Slf4j
public class DesUtils {
    private static final String DES = "DES";

    /**
     * 功能描述: DES加密
     *
     * @param originalContent 原始内容
     * @param key             密钥
     * @return 密文
     * @author LM.X
     * @date 2020/3/31 9:49
     */
    public static String encrypt(String originalContent, String key) {
        if (StrUtil.isEmpty(originalContent) || StrUtil.isEmpty(key)) {
            return null;
        }
        try {
            byte[] encrypt = crypto(originalContent.getBytes(), key.getBytes(), Cipher.ENCRYPT_MODE);
            return Base64.encode(encrypt);
        } catch (Exception e) {
            log.error("DES加密失败", e);
        }
        return null;
    }

    /**
     * 功能描述: DES解密
     *
     * @param cipherContent 密文
     * @param key           密钥
     * @return 明文
     * @author LM.X
     * @date 2020/3/31 10:29
     */
    public static String decrypt(String cipherContent, String key) {
        if (StrUtil.isEmpty(cipherContent) || StrUtil.isEmpty(key)) {
            return null;
        }
        try {
            byte[] encrypt = crypto(Base64.decode(cipherContent), key.getBytes(), Cipher.DECRYPT_MODE);
            return new String(encrypt);
        } catch (Exception e) {
            log.error("DES解密失败", e);
        }
        return null;
    }

    /**
     * 功能描述: 加解密
     *
     * @param content    内容
     * @param key        密钥
     * @param cipherMode 密钥模式，加密：Cipher.ENCRYPT_MODE，解密：Cipher.DECRYPT_MODE
     * @return byte[]
     * @author LM.X
     * @date 2020/3/31 10:04
     */
    private static byte[] crypto(byte[] content, byte[] key, int cipherMode) throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        // 1、生成可信任的随机源
        SecureRandom secureRandom = new SecureRandom();
        // 2、根据原始密钥创建DES密钥对象
        DESKeySpec desKeySpec = new DESKeySpec(key);
        // 3、通过工厂将密钥转换成对称加密 密钥
        SecretKey secretKey = SecretKeyFactory.getInstance(DES).generateSecret(desKeySpec);

        // 4、创建DES的 Cipher对象，以用来完成实际加密操作
        Cipher cipher = Cipher.getInstance(DES);
        // 5、初始化 Cipher对象，主要指定操作类型、密钥以及随机源
        cipher.init(cipherMode, secretKey, secureRandom);

        // 6、doFinal对原始内容进行加密
        return cipher.doFinal(content);
    }

    public static void main(String[] args) {
        final String key = "这是一个密钥";
        final String originalContent = "这是一段测试明文内容。";

        String encrypt = encrypt(originalContent, key);
        log.info("DES 对明文：{} 加密结果为：{}", originalContent, encrypt);

        log.info("DES 对密文：{} 解密结果为：{}", encrypt, decrypt(encrypt, key));
    }
}
