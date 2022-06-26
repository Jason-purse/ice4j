/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ice4j.stack;

import java.util.*;

/**
 * This class encapsulates a STUN transaction ID. It is useful for storing
 * transaction IDs in collection objects as it implements the equals method.
 * It also provides a utility for creating unique transaction IDs.
 *
 * 这个类封装了一个STUN 的事务id(因为事务ID 将存储在集合中所以它实现了equals方法) ...
 * 它也提供了工具为了方便的创建事务ID ...
 *
 * 也就是说,对于请求/ 响应事务,它们的事务id 由STUN 客户端为请求选择 并且 服务器在响应中应答 ...
 * 对于 indications, 由代理选择去发送indication ..
 * 主要作用是关联请求和响应 ... 虽然它也能够扮演一定的角色去帮助抵御一些类型的攻击 ..
 * 服务器也会使用事务id 作为一个key 去独一无二的表示所有客户端的每一个事务 ...
 * 正因如此,事务ID 必须独一无二且随机从 0 .. 2^96-1 次方的区间中选择 并且是一个加密随机数 ..
 * 相同请求的重新发送必须使用相同的事务ID,但是对于新的事务必须选择新的事务ID(除非新请求在位上与以前的请求相同，并且从同一传输地址发送到同一 IP 地址)...
 * 成功 / 错误响应 必须携带相同的事务ID 同它们相关的请求中的事务ID ...
 * 当一个代理作为STUN 服务器 并且也作为STUN 客户端 工作在同一个端口上,那么这个由代理发送的请求中的事务ID 和由这个代理接收到的请求中的事务ID没有任何关系 ...
 *
 * 并且这个事务ID 的最后两个bits 总是 0, 这可以用来区分STUN 包 和其他协议 ...
 *
 *
 *
 *
 * @author Emil Ivov
 */
public class TransactionID
{
    /**
     * RFC5389 Transaction ID length.
     */
    public static final int RFC5389_TRANSACTION_ID_LENGTH = 12;

    /**
     * RFC3489 Transaction ID length.
     * 128-bit -> 16字节
     */
    public static final int RFC3489_TRANSACTION_ID_LENGTH = 16;

    /**
     * The id itself
     */
    private final byte[] transactionID;

    /**
     * Any object that the application would like to correlate to a transaction.
     * 和这个事务关联一个应用的对象 ...
     */
    private Object applicationData = null;

    /**
     * The object to use to generate the rightmost 8 bytes of the id.
     * 这个对象被用来生成 最右边 8位 ..
     */
    private static final Random random
        = new Random(System.currentTimeMillis());

    /**
     * A hashcode for hashtable storage.
     */
    private int hashCode = 0;

    /**
     * Limits access to <tt>TransactionID</tt> instantiation.
     */
    private TransactionID()
    {
        this(false);
    }

    /**
     * Limits access to <tt>TransactionID</tt> instantiation.
     *
     * @param rfc3489Compatibility true to create a RFC3489 transaction ID
     */
    private TransactionID(boolean rfc3489Compatibility)
    {
        transactionID
            = new byte[
                    rfc3489Compatibility
                        ? RFC3489_TRANSACTION_ID_LENGTH
                        : RFC5389_TRANSACTION_ID_LENGTH];
    }

    /**
     * Creates a transaction id object.The transaction id itself is generated
     * using the following algorithm:
     *
     * The first 6 bytes of the id are given the value of
     * <tt>System.currentTimeMillis()</tt>. Putting the right most bits first
     * so that we get a more optimized equals() method.
     *
     * @return A <tt>TransactionID</tt> object with a unique transaction id.
     */
    public static TransactionID createNewTransactionID()
    {
        TransactionID tid = new TransactionID();

        generateTransactionID(tid, 12);
        return tid;
    }

    /**
     * Creates a RFC3489 transaction id object.The transaction id itself is
     * generated using the following algorithm:
     *
     * The first 8 bytes of the id are given the value of
     * <tt>System.currentTimeMillis()</tt>. Putting the right most bits first
     * so that we get a more optimized equals() method.
     *
     * @return A <tt>TransactionID</tt> object with a unique transaction id.
     */
    public static TransactionID createNewRFC3489TransactionID()
    {
        TransactionID tid = new TransactionID(true);

        generateTransactionID(tid, 16);
        return tid;
    }

    /**
     * Generates a random transaction ID
     *
     * 生成一个随机的事务ID ....
     *
     * @param tid transaction ID
     * @param nb number of bytes to generate
     */
    private static void generateTransactionID(TransactionID tid, int nb)
    {
        // 前6位 ..
        long left  = System.currentTimeMillis(); //the first nb/2 bytes of the id
        // 后6位..
        long right = random.nextLong(); //the last nb/2 bytes of the id
        int b = nb / 2;

        for (int i = 0; i < b; i++)
        {
            // 一个long 想要存在 6个字节中 ...
            // long 是8字节 ...
            tid.transactionID[i]   = (byte)((left  >> (i * 8)) & 0xFFL);
            tid.transactionID[i + b] = (byte)((right >> (i * 8)) & 0xFFL);
        }

        //calculate hashcode for Hashtable storage.
        // 计算它的hash 值 用于Hashtable存储 ...
        tid.hashCode =   (tid.transactionID[3] << 24 & 0xFF000000)
                       | (tid.transactionID[2] << 16 & 0x00FF0000)
                       | (tid.transactionID[1] << 8  & 0x0000FF00)
                       | (tid.transactionID[0]       & 0x000000FF);
    }

    /**
     * Returns a <tt>TransactionID</tt> instance for the specified id. If
     * <tt>transactionID</tt> is the ID of a client or a server transaction
     * already known to the stack, then this method would return a reference
     * to that transaction's instance so that we could use it to for storing
     * application data.
     *
     * @param stunStack the <tt>StunStack</tt> in the context of which the
     * request to create a <tt>TransactionID</tt> is being made
     * @param transactionID the value of the ID.
     *
     * @return a reference to the (possibly already existing)
     * <tt>TransactionID</tt> corresponding to the value of
     * <tt>transactionID</tt>
     */
    public static TransactionID createTransactionID(
            StunStack stunStack,
            byte[] transactionID)
    {
        //first check whether we can find a client or a server tran with the
        //specified id.
        StunClientTransaction cliTran
            = stunStack.getClientTransaction(transactionID);

        if (cliTran != null)
            return cliTran.getTransactionID();

        StunServerTransaction serTran
            = stunStack.getServerTransaction(transactionID);

        if (serTran != null)
            return serTran.getTransactionID();

        //seems that the caller really wants a new ID
        TransactionID tid = null;
        tid = new TransactionID((transactionID.length == 16));

        System.arraycopy(transactionID, 0, tid.transactionID, 0,
                tid.transactionID.length);

        //calculate hashcode for Hashtable storage.
        tid.hashCode =   (tid.transactionID[3] << 24 & 0xFF000000)
                       | (tid.transactionID[2] << 16 & 0x00FF0000)
                       | (tid.transactionID[1] << 8  & 0x0000FF00)
                       | (tid.transactionID[0]       & 0x000000FF);

        return tid;
    }

    /**
     * Returns the transaction id byte array (length 12 or 16 if RFC3489
     * compatible).
     *
     * @return the transaction ID byte array.
     */
    public byte[] getBytes()
    {
        return transactionID;
    }

    /**
     * If the transaction is compatible with RFC3489 (16 bytes).
     *
     * @return true if transaction ID is compatible with RFC3489
     */
    public boolean isRFC3489Compatible()
    {
        return (transactionID.length == 16);
    }

    /**
     * Compares two TransactionID objects.
     * @param obj the object to compare with.
     * @return true if the objects are equal and false otherwise.
     */
    public boolean equals(Object obj)
    {
        if (this == obj)
            return true;
        if (!(obj instanceof TransactionID))
            return false;

        byte targetBytes[] = ((TransactionID)obj).transactionID;

        return Arrays.equals(transactionID, targetBytes);
    }

    /**
     * Compares the specified byte array with this transaction id.
     * @param targetID the id to compare with ours.
     * @return true if targetID matches this transaction id.
     */
    public boolean equals(byte[] targetID)
    {
        return Arrays.equals(transactionID, targetID);
    }

    /**
     * Returns the first four bytes of the transactionID to ensure proper
     * retrieval from hashtables.
     * @return the hashcode of this object - as advised by the Java Platform
     * Specification
     */
    public int hashCode()
    {
        return hashCode;
    }

    /**
     * Returns a string representation of the ID
     *
     * @return a hex string representing the id
     */
    public String toString()
    {
        return TransactionID.toString(transactionID);
    }

    /**
     * Returns a string representation of the ID
     *
     * @param transactionID the transaction ID to convert into <tt>String</tt>.
     *
     * @return a hex string representing the id
     */
    public static String toString(byte[] transactionID)
    {
        StringBuilder idStr = new StringBuilder();

        idStr.append("0x");
        for (int i = 0; i < transactionID.length; i++)
        {

            if ((transactionID[i] & 0xFF) <= 15)
                idStr.append("0");

            idStr.append(
                    Integer.toHexString(transactionID[i] & 0xFF).toUpperCase());
        }

        return idStr.toString();
    }

    /**
     * Stores <tt>applicationData</tt> in this ID so that we can refer back to
     * it if we ever need to at a later stage (e.g. when receiving a response
     * to a {@link StunClientTransaction}).
     *
     * @param applicationData a reference to the {@link Object} that the
     * application would like to correlate to the transaction represented by
     * this ID.
     */
    public void setApplicationData(Object applicationData)
    {
        this.applicationData = applicationData;
    }

    /**
     * Returns whatever <tt>applicationData</tt> was previously stored in this
     * ID.
     *
     * @return a reference to the {@link Object} that the application may have
     * stored in this ID's application data field.
     */
    public Object getApplicationData()
    {
        return applicationData;
    }
}
