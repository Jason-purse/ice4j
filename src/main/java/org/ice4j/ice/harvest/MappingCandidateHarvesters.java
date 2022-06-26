/*
 * Copyright @ 2015-2016 Atlassian Pty Ltd
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
package org.ice4j.ice.harvest;

import org.ice4j.*;
import org.jetbrains.annotations.*;
import org.jitsi.utils.concurrent.*;

import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;

import static org.ice4j.ice.harvest.HarvestConfig.config;

/**
 * Manages a static list of {@link MappingCandidateHarvester} instances, created
 * according to configuration provided as system properties.
 *
 * 管理一个静态列表实例(MappingCandidateHarvester) 根据提供的作为系统属性的配置创建  ..
 *
 * The instances in the set are safe to use by any {@code Agent}s.
 * 这个实例在任何Agent中使用都是安全的 ..
 *
 * @author Damian Minkov
 * @author Boris Grozev
 */
public class MappingCandidateHarvesters
{
    /**
     * The {@link Logger} used by the {@link MappingCandidateHarvesters}
     * class for logging output.
     */
    private static final Logger logger = Logger.getLogger(MappingCandidateHarvesters.class.getName());

    /**
     * Whether {@link #harvesters} has been initialized.
     */
    private static boolean initialized = false;

    /**
     * The list of already configured harvesters.
     */
    private static MappingCandidateHarvester[] harvesters
            = new MappingCandidateHarvester[0];

    /**
     * Whether the discovery of a public address via STUN has failed.
     * It is considered failed if the configuration included at least one STUN
     * server, but we failed to receive at least one valid response.
     * Note that this defaults to false and is only raised after we are certain
     * we failed (i.e. after our STUN transactions timeout).
     */
    public static boolean stunDiscoveryFailed = false;

    /**
     * @return the list of configured harvesters.
     */
    public static MappingCandidateHarvester[] getHarvesters()
    {
        initialize();
        return harvesters;
    }

    /**
     * @return  the (first) mapping harvester which matches a given public address, or {@code null} if none match it.
     */
    public static MappingCandidateHarvester findHarvesterForAddress(TransportAddress publicAddress)
    {
        for (MappingCandidateHarvester harvester : harvesters)
        {
            if (harvester.publicAddressMatches(publicAddress))
            {
                return harvester;
            }
        }
        return null;
    }

    /**
     *
     * 初始化收割机 ...
     * 首先他会读取配置 并实例化 harvester ...
     * 等待它们初始化(这也许包含了网络交流 并且会花费很长一段时间) ..
     * 然后它移除可能失败初始化的harvesters ... 并且移除可能使用重复地址的harvesters ...
     * Initializes {@link #harvesters}.
     * First it reads the configuration and instantiates harvesters accordingly,
     * waiting for their initialization (which may include network communication
     * and thus take a long time). Then it removes harvesters which failed to
     * initialize properly and remove any harvesters with duplicate addresses.
     *
     * Three types of mapping harvesters are supported: NAT (with
     * pre-configured addresses), AWS and STUN.
     *
     * 支持三种 映射(绘制)收割机 (NAT(预先配置地址,AWS以及 STUN) ...
     */
    public static synchronized void initialize()
    {
        if (initialized)
            return;
        initialized = true;

        long start = System.currentTimeMillis();
        List<MappingCandidateHarvester> harvesterList = new LinkedList<>();

        // 查询静态映射 ... 增加候选 ...
        for (HarvestConfig.StaticMapping staticMapping : config.getStaticMappings())
        {
            logger.info("Adding a static mapping: " + staticMapping);
            // 默认没有端口,使用 9 ,一般来说,我们需要设置内外映射 ... 以及端口 ...
            // If the configuration has no port, then the port value is not used in any way. We put 9 (for "discard")
            // as a filler.
            int localPort = staticMapping.getLocalPort() != null ? staticMapping.getLocalPort() : 9;
            int publicPort = staticMapping.getPublicPort() != null ? staticMapping.getPublicPort() : 9;
            // 设置本地地址 ...
            TransportAddress localAddress
                    = new TransportAddress(staticMapping.getLocalAddress(), localPort, Transport.UDP);
            // 设置公开地址 ...
            TransportAddress publicAddress
                    = new TransportAddress(staticMapping.getPublicAddress(), publicPort, Transport.UDP);
            // 增加一个静态映射候选Harvester ...
            harvesterList.add(new StaticMappingCandidateHarvester(
                    publicAddress,
                    localAddress,
                    staticMapping.getName(),
                    staticMapping.getLocalPort() != null));
        }


        // AWS harvester
        boolean enableAwsHarvester = config.enableAwsHarvester();
        if (enableAwsHarvester && (config.forceAwsHarvester() || AwsCandidateHarvester.smellsLikeAnEC2()))
        {
            logger.info("Using AwsCandidateHarvester.");
            harvesterList.add(new AwsCandidateHarvester());
        }


        // STUN harvesters
        // stun 服务器 ...
        List<String> stunServers = config.stunMappingCandidateHarvesterAddresses();
        if (!stunServers.isEmpty())
        {
            // Create STUN harvesters (and wait for all of their discovery to finish).
            // 创建STUN 收割机(等待它们所有的发现完成,它们将发现所有的候选者 ...) ...
            List<StunMappingCandidateHarvester> stunHarvesters = createStunHarvesters(stunServers);

            // We have STUN servers configured, so flag failure if none of them were able to discover an address.
            stunDiscoveryFailed = stunHarvesters.isEmpty();

            harvesterList.addAll(stunHarvesters);
        }

        harvesterList = prune(harvesterList);
        harvesters = harvesterList.toArray(new MappingCandidateHarvester[harvesterList.size()]);

        for (MappingCandidateHarvester harvester : harvesters)
        {
            logger.info("Using " + harvester);
        }
        logger.info("Initialized mapping harvesters (delay="
                        + (System.currentTimeMillis() - start) + "ms). "
                        + " stunDiscoveryFailed=" + stunDiscoveryFailed);
    }

    /**
     * Prunes a list of mapping harvesters, removing the ones without valid
     * addresses and those with duplicate addresses.
     *
     * 映射收割机的纯列表,移除无效的地址 或者已经重复的地址 ...
     * @param harvesters the list of harvesters.
     * @return the pruned list.
     */
    private static List<MappingCandidateHarvester> prune(
        List<MappingCandidateHarvester> harvesters)
    {
        List<MappingCandidateHarvester> pruned = new LinkedList<>();
        for (MappingCandidateHarvester harvester : harvesters)
        {
            maybeAdd(harvester, pruned);
        }
        return pruned;
    }

    /**
     * Adds {@code harvester} to {@code harvesters}, if it has valid addresses
     * and {@code harvesters} doesn't already contain a harvester with the same
     * addresses.
     * @param harvester the harvester to add.
     * @param harvesters the list to add to.
     */
    private static void maybeAdd(
        MappingCandidateHarvester harvester,
        List<MappingCandidateHarvester> harvesters)
    {
        TransportAddress face = harvester.getFace();
        TransportAddress mask = harvester.getMask();
        if (face == null || mask == null || face.equals(mask))
        {
            logger.info("Discarding a mapping harvester: " + harvester);
            return;
        }

        for (MappingCandidateHarvester h : harvesters)
        {
            if (face.getAddress().equals(h.getFace().getAddress())
                && mask.getAddress().equals(h.getMask().getAddress()))
            {
                logger.info("Discarding a mapping harvester with duplicate addresses: " + harvester + ". Kept: " + h);
                return;
            }
        }

        harvesters.add(harvester);
    }

    /**
     * Creates STUN mapping harvesters for each of the given STUN servers, and
     * waits for address discovery to finish for all of them.
     *
     * 创建一个STUN mapping harvesters(为每一个给定的STUN 服务器) 并等待它们完成所有的地址发现 ...
     * @param stunServers an array of STUN server addresses (ip_address:port
     * pairs).
     * @return  the list of those who were successful in discovering an address.
     */
    private static List<StunMappingCandidateHarvester> createStunHarvesters(@NotNull List<String> stunServers)
    {
        List<StunMappingCandidateHarvester> stunHarvesters = new LinkedList<>();

        List<Callable<StunMappingCandidateHarvester>> tasks = new LinkedList<>();

        // Create a StunMappingCandidateHarvester for each local:remote address
        // pair.
        List<InetAddress> localAddresses
            = HostCandidateHarvester.getAllAllowedAddresses();
        for (String stunServer : stunServers)
        {
            String[] addressAndPort = stunServer.split(":");
            if (addressAndPort.length < 2)
            {
                logger.severe("Failed to parse STUN server address: "
                                  + stunServer);
                continue;
            }
            int port;
            try
            {
                port = Integer.parseInt(addressAndPort[1]);
            }
            catch (NumberFormatException nfe)
            {
                logger.severe("Invalid STUN server port: " + addressAndPort[1]);
                continue;
            }


            TransportAddress remoteAddress
                = new TransportAddress(
                addressAndPort[0],
                port,
                Transport.UDP);

            for (InetAddress localInetAddress : localAddresses)
            {
                if (localInetAddress instanceof Inet6Address)
                {
                    // This is disabled, because it is broken for an unknown
                    // reason and it is not currently needed.
                    continue;
                }

                TransportAddress localAddress
                    = new TransportAddress(localInetAddress, 0, Transport.UDP);

                logger.info("Using " + remoteAddress + " for StunMappingCandidateHarvester (localAddress="
                        + localAddress + ").");
                final StunMappingCandidateHarvester stunHarvester
                    = new StunMappingCandidateHarvester(
                            localAddress,
                            remoteAddress);

                Callable<StunMappingCandidateHarvester> task = () ->
                {
                    stunHarvester.discover();
                    return stunHarvester;
                };
                tasks.add(task);
            }
        }

        // Now run discover() on all created harvesters in parallel and pick
        // the ones which succeeded.
        // 并发运行, 然后等待所有的discover 完成 ...
        ExecutorService es = ExecutorFactory.createFixedThreadPool(tasks.size(), "ice4j.Harvester-executor-");

        try
        {
            List<Future<StunMappingCandidateHarvester>> futures;
            try
            {
                futures = es.invokeAll(tasks);
            }
            catch (InterruptedException ie)
            {
                Thread.currentThread().interrupt();
                return stunHarvesters;
            }

            for (Future<StunMappingCandidateHarvester> future : futures)
            {
                try
                {
                    StunMappingCandidateHarvester harvester = future.get();

                    // The STUN server replied successfully.
                    // 这个收割机 获取到了面具 ..
                    if (harvester.getMask() != null)
                    {
                        // 表示这是有效的 收割机 ...
                        stunHarvesters.add(harvester);
                    }
                }
                catch (ExecutionException ee)
                {
                    // The harvester failed for some reason, discard it.
                }
                catch (InterruptedException ie)
                {
                    // 如果等待结果的过程中发生了当前线程打断 .., 那么重新设置打断状态,并抛出异常 ..
                    Thread.currentThread().interrupt();
                    throw new RuntimeException(ie);
                }
            }
        }
        finally
        {
            es.shutdown();
        }
        return stunHarvesters;
    }

    /**
     * Prevent instance creation.
     */
    private MappingCandidateHarvesters()
    {
    }
}
