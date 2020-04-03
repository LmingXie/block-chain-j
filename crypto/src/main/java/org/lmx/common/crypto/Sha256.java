package org.lmx.common.crypto;

import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.digest.DigestUtil;

import java.nio.ByteBuffer;


/**
 * 提供一种{@code hash（byte []）}方法，用于使用SHA-256对消息进行哈希处理。
 */
public class Sha256 {

    /**
     * 初始化常量：8个初始Hash值
     * <pre>
     *     取自自然数中前面8个素数(2,3,5,7,11,13,17,19)的 “<strong>平方根</strong>” 的小数部分, 并且取前面的32位.
     * </pre>
     */
    private static final int[] H0 = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
            0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    /**
     * 初始化常量：64个常数密钥
     * <pre>
     *     取自自然数中前面64个素数的 “<strong>立方根</strong>” 的小数部分的前32位,
     *     用16进制表示, 则相应的常数序列如下:
     * </pre>
     */
    private static final int[] K = {0x428a2f98, 0x71374491, 0xb5c0fbcf,
            0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74,
            0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
            0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc,
            0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
            0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb,
            0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70,
            0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3,
            0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f,
            0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2};


    /**
     * 块数组
     */
    private static final int[] W = new int[64];
    /**
     * 用来存储加密后的结果
     */
    private static final int[] H = new int[8];
    /**
     *
     */
    private static final int[] TEMP = new int[8];

    public static String sha256Hex(String message) {
        return HexUtil.encodeHexStr(hash(message.getBytes()));
    }

    /**
     * 使用SHA-256对给定的消息进行哈希处理并返回哈希值。
     *
     * @param message 要哈希的字节。
     * @return 哈希后的字节。
     */
    public static byte[] hash(byte[] message) {
        // 设 H = H0
        System.arraycopy(H0, 0, H, 0, H0.length);

        /*
            1、初始化所有字（对应“补位”操作），返回的结果是所有的“块”
            SHA256算法中的最小运算单元称为“字”（Word），1 word(字) = 32 bit(位)

            toIntArray()将byte转换成了int，1 int = 4 byte = 32 bit，也1 int就是一个字。
         */
        int[] words = toIntArray(pad(message));

        /*
          2、构造64个字（word）

         原文：break chunk into sixteen 32-bit big-endian words w[0], …, w[15].
         译文：对于每一块，将块分解为16个32-bit的big-endian的字，记为w[0], …, w[15]。

          将“字”转换成“块”，即将“字”数组，按每16个字一个“块”进行组装。一个“块” = 512 bit = 16 word字。
          代码中通过除以16来表示一个“块”，并没有真实创建“块”。
         */
        for (int i = 0, n = words.length / 16; i < n; ++i) {

            // 2.1、前16个字直接由消息的第i个块分解得到
            System.arraycopy(words, i * 16, W, 0, 16);

            /*
               2.2、其余的字由如下迭代公式得到：
               W[t]​= σ1​(W[t] − 2) + W[t−7]​+ σ0(W[t] − 15) + W[t]− 16​

               最后将得到64个“字”。
             */
            for (int t = 16; t < W.length; ++t) {
                // 根据加法交换律，修改先后顺序不印象最终结果
                W[t] = smallSig1(W[t - 2])
                        + W[t - 7]
                        + smallSig0(W[t - 15])
                        + W[t - 16];
            }

            /*
               3、循环对“块”加密：也就是说循环64次。
               例如：对“abc”加密时，就相当于依次对 c、b、a进行加密，c的加密结果，保存到a位置
             */

            // 设 TEMP = H，H是初始变量，即8个初始hash值，也就是前8个质数的平方根的前32bit位。
            System.arraycopy(H, 0, TEMP, 0, H.length);

            // 在TEMP上操作
            for (int t = 0; t < W.length; ++t) {
                // t1 = H[7] + Ch(H[4],H[5],H[6]) + Σ1(H[4])
                int t1 = TEMP[7]
                        + ch(TEMP[4], TEMP[5], TEMP[6]) + K[t] + W[t]
                        + bigSig1(TEMP[4]);

                // t2 = Ma(H[0],H[1],H[2]) + Σ0(H[0])
                int t2 = maj(TEMP[0], TEMP[1], TEMP[2]) + bigSig0(TEMP[0]);
                System.arraycopy(TEMP, 0, TEMP, 1, TEMP.length - 1);

                // 设置中间散列
                TEMP[4] += t1;

                // 设置头部散列 t1 + t2
                TEMP[0] = t1 + t2;
            }

            // 将TEMP中的值添加到H中的值
            for (int t = 0; t < H.length; ++t) {
                H[t] += TEMP[t];
            }

        }
        return toByteArray(H);
    }

    /**
     * 填充给定消息的长度
     * 512位（64字节）的倍数，包括添加 1位，k 0位以及消息长度为64位整数。
     * <pre>
     * <strong>注意：Java操作的是byte，1 byte = 8 bit，因此在执行算法是有所差别。</strong>
     * <strong>1 byte = 8 bit</strong>
     * <strong>1 word = 32 bit = 4 byte</strong>
     * <strong>1 int = 4 byte</strong>
     *
     * 补位操作遵循如下方程式：
     *    <strong>l + 1 + k ≡ 448 mod 512</strong>
     *    其中，l 是二进制消息message（简称M）的长度，k为补0操作的个数，为未知变量，可通过代入l可求得。
     *
     *  我们以“abc”为例：
     *    原始字符    ASCII码    二进制编码
     *      a          97         01100001
     *      b          98         01100010
     *      c          99         01100011
     *    因此，其二进制形式为：01100001 01100010 01100011，长度l = 24。
     *
     *    1.1 补1，即直接在二进制消息尾部添加 1；
     *    例如：消息“abc”的二进制位，补1后 01100001 01100010 01100011 1。
     *
     *    1.2 补0，个数为 k，代入消息长度l可求得；
     *    例如：代入l算得 k = 448 - l -1 = 423，因此补 423个0。
     *    由于448 < 512，因此，可忽略掉后面的mod 512（对整数取模时，若整数小于模数，则取模结果为本身）。
     *
     *    1.3 补入消息长度l的64位二进制内容。
     *    例如：消息“abc”的二进制长度为24，则最后进行的补位操作就是将24的二进制形式 ‭00011000‬
     * </pre>
     *
     * @param message 要填充的消息。
     * @return 一个带有填充消息字节的新数组。
     */
    public static byte[] pad(byte[] message) {
        final int blockBits = 512;
        final int blockBytes = blockBits / 8;

        // 新消息长度：原始长度 + (补位的)1位 + 填充8字节长度（也就是64bit）
        int newMessageLength = message.length + 1 + 8;
        int padBytes = blockBytes - (newMessageLength % blockBytes);
        newMessageLength += padBytes;

        // 将消息复制到扩展数组
        final byte[] paddedMessage = new byte[newMessageLength];
        System.arraycopy(message, 0, paddedMessage, 0, message.length);

        // 第一步，补位：在消息末尾补上一位"1"。0b代表二进制，10000000 是二进制的128
        paddedMessage[message.length] = (byte) 0b10000000;

        // 第二步，跳过，因为我们已经设置了padBytes数组的长度，所以内部所有元素已经是0了（默认值）

        // 第三步，补入消息长度l的64位二进制的8字节整数，（java使用的是byte，1 byte = 8 bit）
        int lenPos = message.length + 1 + padBytes;
        ByteBuffer.wrap(paddedMessage, lenPos, 8).putLong(message.length * 8);
        return paddedMessage;
    }

    /**
     * 将给定的byte数组转换成字集合（也就是int数组，因为 1 int = 4 byte）
     *
     * @param bytes 源数组
     * @return 转换后的数组.
     */
    public static int[] toIntArray(byte[] bytes) {
        if (bytes.length % Integer.BYTES != 0) {
            throw new IllegalArgumentException("byte array length");
        }

        ByteBuffer buf = ByteBuffer.wrap(bytes);

        int[] result = new int[bytes.length / Integer.BYTES];
         for (int i = 0; i < result.length; ++i) {
            result[i] = buf.getInt();
        }

        return result;
    }

    /**
     * 通过big-endian转换将给定的int数组转换为字节数组（1 int变为4个字节）。
     *
     * @param ints 源数组.
     * @return 转换后的数组.
     */
    public static byte[] toByteArray(int[] ints) {
        ByteBuffer buf = ByteBuffer.allocate(ints.length * Integer.BYTES);
        for (int i = 0; i < ints.length; ++i) {
            buf.putInt(ints[i]);
        }

        return buf.array();
    }
    /*=================== 以下为6个运算函数，对于每一个块都会循环使用这6个位运算函数进行加密运算 ======================*/

    /**
     * 功能描述: <br>
     * 此函数满足如下方程式：<br>
     *
     * <pre>
     *     <strong>Ch(x,y,z) = (x∧y)⊕(¬x∧z)</strong>
     *
     *    <strong>公式逻辑运算符</strong>   <strong>Java逻辑运算符</strong>   <strong>含 义</strong>
     *      ∧                &          按位“与”
     *      ¬                ~          按位“补/非”
     *     ⊕                |          按位“异/或”
     *     S^n           rotateRight() 循环右移n个bit
     *     R^n              >>>         右移n个bit
     * </pre>
     *
     * @param x
     * @param y
     * @param z
     * @return int
     * @author LM.X
     * @date 2020/4/2 10:08
     */
    private static int ch(int x, int y, int z) {
        return (x & y) | ((~x) & z);
    }

    /**
     * 功能描述:
     * <br>
     * 此函数满足如下方程式：<br>
     *
     * <pre>
     *     <strong>Ma(x,y,z)=(x∧y)⊕(x∧z)⊕(y∧z)</strong>
     *
     *    <strong>公式逻辑运算符</strong>   <strong>Java逻辑运算符</strong>   <strong>含 义</strong>
     *      ∧                &          按位“与”
     *      ¬                ~          按位“补/非”
     *     ⊕                |          按位“异/或”
     *     S^n           rotateRight() 循环右移n个bit
     *     R^n              >>>         右移n个bit
     * </pre>
     *
     * @param x
     * @param y
     * @param z
     * @return int
     * @author LM.X
     * @date 2020/4/2 10:08
     */
    private static int maj(int x, int y, int z) {
        return (x & y) | (x & z) | (y & z);
    }

    /**
     * 功能描述:
     * <br>
     * 此函数满足如下方程式：<br>
     *
     * <pre>
     *     <strong>Σ0​(x)=S^2(x)⊕S^13(x)⊕S^22(x)</strong>
     *
     *    <strong>公式逻辑运算符</strong>   <strong>Java逻辑运算符</strong>   <strong>含 义</strong>
     *      ∧                &          按位“与”
     *      ¬                ~          按位“补/非”
     *     ⊕                |          按位“异/或”
     *     S^n           rotateRight() 循环右移n个bit
     *     R^n              >>>         右移n个bit
     * </pre>
     *
     * @param x
     * @return int
     * @author LM.X
     * @date 2020/4/2 10:14
     */
    private static int bigSig0(int x) {
        return Integer.rotateRight(x, 2) ^ Integer.rotateRight(x, 13)
                ^ Integer.rotateRight(x, 22);
    }

    /**
     * 功能描述:
     * <br>
     * 此函数满足如下方程式：<br>
     *
     * <pre>
     *     <strong>Σ1​(x)=S^6(x)⊕S^11(x)⊕S^25(x)</strong>
     *
     *    <strong>公式逻辑运算符</strong>   <strong>Java逻辑运算符</strong>   <strong>含 义</strong>
     *      ∧                &          按位“与”
     *      ¬                ~          按位“补/非”
     *     ⊕                |          按位“异/或”
     *     S^n           rotateRight() 循环右移n个bit
     *     R^n              >>>         右移n个bit
     * </pre>
     *
     * @param x
     * @return int
     * @author LM.X
     * @date 2020/4/2 10:19
     */
    private static int bigSig1(int x) {
        return Integer.rotateRight(x, 6) ^ Integer.rotateRight(x, 11)
                ^ Integer.rotateRight(x, 25);
    }

    /**
     * 功能描述:
     * <br>
     * 此函数满足如下方程式：<br>
     *
     * <pre>
     *     <strong>σ0​(x)=S^7(x)⊕S^18(x)⊕R^3(x)</strong>
     *
     *    <strong>公式逻辑运算符</strong>   <strong>Java逻辑运算符</strong>   <strong>含 义</strong>
     *      ∧                &          按位“与”
     *      ¬                ~          按位“补/非”
     *     ⊕                |          按位“异/或”
     *     S^n           rotateRight() 循环右移n个bit
     *     R^n              >>>         右移n个bit
     * </pre>
     *
     * @param x
     * @return int
     * @author LM.X
     * @date 2020/4/2 10:20
     */
    private static int smallSig0(int x) {
        return Integer.rotateRight(x, 7) ^ Integer.rotateRight(x, 18)
                ^ (x >>> 3);
    }

    /**
     * 功能描述:
     * <br>
     * 此函数满足如下方程式：<br>
     *
     * <pre>
     *     <strong>σ1​(x)=S^17(x)⊕S^19(x)⊕R^10(x)</strong>
     *
     *    <strong>公式逻辑运算符</strong>   <strong>Java逻辑运算符</strong>   <strong>含 义</strong>
     *      ∧                &          按位“与”
     *      ¬                ~          按位“补/非”
     *     ⊕                |          按位“异/或”
     *     S^n           rotateRight() 循环右移n个bit
     *     R^n              >>>         右移n个bit
     * </pre>
     *
     * @param x
     * @return int
     * @author LM.X
     * @date 2020/4/2 10:21
     */
    private static int smallSig1(int x) {
        return Integer.rotateRight(x, 17) ^ Integer.rotateRight(x, 19)
                ^ (x >>> 10);
    }

    public static void main(String[] args) {
        System.out.println("手写SHA-256加密结果：" + sha256Hex("abc"));

        System.out.println("HuTool工具SHA-256加密结果：" + DigestUtil.sha256Hex("abc"));
    }
}
