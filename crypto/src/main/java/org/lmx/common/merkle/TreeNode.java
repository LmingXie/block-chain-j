package org.lmx.common.merkle;

import cn.hutool.crypto.digest.DigestUtil;
import lombok.Data;

/**
 * 功能描述：Merkle叶子节点
 *
 * @program: block-chain-j
 * @author: LM.X
 * @create: 2020-03-31 14:39
 **/
@Data
public class TreeNode {
    /**
     * 左子节点
     */
    private TreeNode left;
    /**
     * 右子节点
     */
    private TreeNode right;
    /**
     * （孩子）节点数据
     */
    private String data;
    /**
     * SHA-256的data
     */
    private String hash;

    public TreeNode(){}
    public TreeNode(String data) {
        this.data = data;
        this.hash = DigestUtil.sha256Hex(data);
    }
}
