package org.lmx.common.merkle;

import cn.hutool.core.collection.CollectionUtil;
import cn.hutool.core.util.ObjectUtil;
import cn.hutool.crypto.digest.DigestUtil;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;

/**
 * 功能描述：Merkle算法实现
 *
 * @program: block-chain-j
 * @author: LM.X
 * @create: 2020-03-31 14:53
 **/
@Slf4j
public class MerkleTree {
    /**
     * 交易列表
     */
    private List<TreeNode> treeNodes;

    /**
     * 根节点
     */
    private TreeNode root;

    public MerkleTree(List<String> treeNodes) {
        createMerkleTree(treeNodes);
    }

    /**
     * 功能描述: 构建默克尔树
     *
     * @param transactions 内容列表
     * @return void
     * @author LM.X
     * @date 2020/3/31 14:58
     */
    private void createMerkleTree(List<String> transactions) {
        if (CollectionUtil.isEmpty(transactions)) {
            return;
        }

        // 初始化列表
        this.treeNodes = new ArrayList();

        // 格式化节点信息
        treeNodes.addAll(createLeafNode(transactions));

        // 合并叶子节点，获取默克尔根
        while (true) {
            treeNodes = createParentList(treeNodes);
            if (treeNodes.size() < 2) {
                root = treeNodes.get(0);
                return;
            }
        }
    }

    /**
     * 功能描述: 创建叶子节点
     *
     * @param transactions 内容列表
     * @return 返回叶子节点列表
     * @author LM.X
     * @date 2020/3/31 15:09
     */
    private List<TreeNode> createLeafNode(List<String> transactions) {
        List<TreeNode> leafs = new ArrayList();
        if (CollectionUtil.isEmpty(transactions)) {
            return leafs;
        }

        for (String transaction : transactions) {
            leafs.add(new TreeNode(transaction));
        }

        return leafs;
    }

    /**
     * 功能描述: 合并所以叶子节点
     *
     * @param nodes 节点列表
     * @return 返回合并后的节点集合
     * @author LM.X
     * @date 2020/3/31 15:41
     */
    private List<TreeNode> createParentList(List<TreeNode> nodes) {
        List parents = new ArrayList();
        if (CollectionUtil.isEmpty(nodes)) {
            return parents;
        }

        int len = nodes.size();

        for (int i = 0; i < len - 1; i += 2) {
            parents.add(createParentNode(nodes.get(i), nodes.get(i + 1)));
        }

        // 当奇数个叶子节点时，单独处理
        if (len % 2 != 0) {
            parents.add(createParentNode(nodes.get(len - 1), null));
        }

        log.info("本轮合并后，节点长度：{}", parents.size());
        return parents;
    }

    /**
     * 功能描述: 合并左右子节点
     *
     * @param left  左子节点
     * @param right 右子节点
     * @return 返回合并后的父节点
     * @author LM.X
     * @date 2020/3/31 15:35
     */
    private TreeNode createParentNode(TreeNode left, TreeNode right) {
        TreeNode parent = new TreeNode();
        parent.setLeft(left);
        parent.setRight(right);

        String lh = left.getHash();
        String rh = right.getHash();

        String hash = ObjectUtil.isEmpty(right) ? lh : doubleSHA256(lh, rh);

        parent.setData(hash);
        parent.setHash(hash);
        log.info("合并【{}，{}】，创建父节点：{}", left.getData(), ObjectUtil.isEmpty(right) ?
                null : right.getData(), hash);
        return parent;
    }

    /**
     * 功能描述: 双哈希运算
     *
     * @param lh
	 * @param rh
     * @return SHA256 结果
     * @author LM.X
     * @date 2020/3/31 16:02
     */
    private String doubleSHA256(String lh, String rh) {
        return DigestUtil.sha256Hex(DigestUtil.sha256Hex(lh + rh));
    }

    public static void main(String[] args) {
        List<String> txs = new ArrayList() {{
            add("1");add("2");add("3");add("4");
            add("5");add("6");add("7");add("8");
            add("9");add("10");add("11");add("12");
            add("13");add("14");add("15");add("16");
        }};

        MerkleTree merkleTree = new MerkleTree(txs);
        log.info("获取到的默克尔根为：{}", merkleTree.root.getHash());
    }
}
