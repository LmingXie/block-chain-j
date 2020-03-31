package org.lmx.common.crypto;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.ObjectUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import lombok.extern.slf4j.Slf4j;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 功能描述：非对称加密RSA算法工具类
 *
 * @program: block-chain-j
 * @author: LM.X
 * @create: 2020-03-31 12:27
 **/
@Slf4j
public class RsaUtils {

    /**
     * 功能描述: （非对称）RSA 公钥加密
     *
     * @param originalContent 明文
     * @param publicKey       私钥[type:java.security.PrivateKey]
     * @return 返回密文
     * @author LM.X
     * @date 2020/3/31 13:02
     */
    public static String rsaEnCrypt(String originalContent, PublicKey publicKey) {
        if (StrUtil.isEmpty(originalContent) || ObjectUtil.isEmpty(publicKey)) {
            log.info("RSA 公钥加密参数异常。原因：originalContent：{}，publicKey：{}", originalContent, publicKey);
            return null;
        }
        RSA rsa = new RSA();
        rsa.setPublicKey(publicKey);
        return rsa.encryptBase64(originalContent, KeyType.PublicKey);
    }

    /**
     * 功能描述: （非对称）RSA 私钥解密
     *
     * @param originalContent 明文
     * @param privateKey      公钥[type:java.security.PublicKey]
     * @return 返回明文
     * @author LM.X
     * @date 2020/3/31 13:02
     */
    public static String rsaDeCrypt(String originalContent, PrivateKey privateKey) {
        if (StrUtil.isEmpty(originalContent) || ObjectUtil.isEmpty(privateKey)) {
            log.info("RSA 私钥解密参数异常。原因：originalContent：{}，privateKey：{}", originalContent, privateKey);
            return null;
        }
        RSA rsa = new RSA();
        rsa.setPrivateKey(privateKey);
        return rsa.decryptStr(originalContent, KeyType.PrivateKey);
    }

    /**
     * 功能描述: （非对称）RSA 公钥加密
     *
     * @param originalContent 明文
     * @param publicKey       私钥[type:String]
     * @return 返回明文
     * @author LM.X
     * @date 2020/3/31 13:02
     */
    public static String rsaEnCrypt(String originalContent, String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (StrUtil.isEmpty(publicKey)) {
            log.info("RSA 公钥加密参数异常。原因：publicKey：{}", publicKey);
            return null;
        }

        KeyFactory key = KeyFactory.getInstance("RSA");
        PublicKey pubKey = key.generatePublic(new X509EncodedKeySpec(Base64.decode(publicKey)));
        return rsaEnCrypt(originalContent, pubKey);
    }

    /**
     * 功能描述: （非对称）RSA 私钥解密
     *
     * @param originalContent 明文
     * @param privateKey      公钥[type:String]
     * @return 返回明文
     * @throws NoSuchAlgorithmException Or InvalidKeySpecException
     * @author LM.X
     * @date 2020/3/31 13:11
     */
    public static String rsaDeCrypt(String originalContent, String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (StrUtil.isEmpty(privateKey)) {
            log.info("RSA 私钥解密参数异常。原因：privateKey：{}", privateKey);
            return null;
        }

        KeyFactory key = KeyFactory.getInstance("RSA");
        PrivateKey priKey = key.generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(privateKey)));
        return rsaDeCrypt(originalContent, priKey);
    }

    /**
     * 功能描述:  String转公钥PublicKey
     *
     * @param publicKey 公钥
     * @return PublicKey 公钥对象
     * @author LM.X
     * @date 2020/3/31 13:11
     */
    public static PublicKey getPublicKey(String publicKey) throws Exception {
        KeyFactory key = KeyFactory.getInstance("RSA");
        PublicKey pubKey = key.generatePublic(new X509EncodedKeySpec(Base64.decode(publicKey)));
        return pubKey;
    }

    /**
     * String转私钥PrivateKey
     *
     * @param privateKey 私钥
     * @return PrivateKey 公钥对象
     * @throws Exception
     */
    public static PrivateKey getPrivateKey(String privateKey) throws Exception {
        KeyFactory key = KeyFactory.getInstance("RSA");
        PrivateKey priKey = key.generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(privateKey)));
        return priKey;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String originalContent = "这是一段RSA加密明文。";
        RSA rsa = new RSA();

        String crypt = rsaEnCrypt(originalContent, rsa.getPublicKey());
        log.info("对明文公钥加密结果：{}", crypt);
        log.info("对明文私钥解密结果：{}", rsaDeCrypt(crypt, rsa.getPrivateKey()));

        log.info("=====================进行方法2测试=============================");

        String privateKeyBase64 = rsa.getPrivateKeyBase64();
        String publicKeyBase64 = rsa.getPublicKeyBase64();
        log.info("获取私钥：{}", privateKeyBase64);
        log.info("获取公钥：{}", publicKeyBase64);
        log.info("2对明文公钥加密结果：{}", rsaEnCrypt(originalContent, publicKeyBase64));
        log.info("2对明文私钥解密结果：{}", rsaDeCrypt(crypt, privateKeyBase64));

    }
}
