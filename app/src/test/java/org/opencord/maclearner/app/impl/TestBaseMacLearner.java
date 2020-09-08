/*
 * Copyright 2017-present Open Networking Foundation
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
package org.opencord.maclearner.app.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import org.onlab.junit.TestUtils;
import org.onlab.packet.ChassisId;
import org.onlab.packet.DHCP;
import org.onlab.packet.EthType;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.UDP;
import org.onlab.packet.VlanId;
import org.onlab.packet.dhcp.DhcpOption;
import org.onosproject.cfg.ComponentConfigAdapter;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.cluster.ClusterServiceAdapter;
import org.onosproject.cluster.ControllerNode;
import org.onosproject.cluster.DefaultControllerNode;
import org.onosproject.cluster.NodeId;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.core.CoreServiceAdapter;
import org.onosproject.event.DefaultEventSinkRegistry;
import org.onosproject.event.Event;
import org.onosproject.event.EventDeliveryService;
import org.onosproject.event.EventSink;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DefaultDevice;
import org.onosproject.net.DefaultHost;
import org.onosproject.net.DefaultLink;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.HostLocation;
import org.onosproject.net.Link;
import org.onosproject.net.config.Config;
import org.onosproject.net.config.ConfigApplyDelegate;
import org.onosproject.net.config.basics.HostLearningConfig;
import org.onosproject.net.config.basics.HostLearningConfigTest;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceServiceAdapter;
import org.onosproject.net.host.HostDescription;
import org.onosproject.net.host.HostProvider;
import org.onosproject.net.host.HostProviderService;
import org.onosproject.net.host.HostServiceAdapter;
import org.onosproject.net.link.LinkServiceAdapter;
import org.onosproject.net.packet.DefaultInboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketContextAdapter;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketServiceAdapter;
import org.onosproject.net.provider.AbstractProviderService;
import org.onosproject.net.provider.ProviderId;
import org.onosproject.net.topology.Topology;
import org.onosproject.net.topology.TopologyServiceAdapter;
import org.onosproject.store.service.AsyncConsistentMap;
import org.onosproject.store.service.AsyncDistributedSet;
import org.onosproject.store.service.AtomicCounter;
import org.onosproject.store.service.ConsistentMap;
import org.onosproject.store.service.ConsistentMapAdapter;
import org.onosproject.store.service.ConsistentMapBuilder;
import org.onosproject.store.service.DistributedSet;
import org.onosproject.store.service.DistributedSetAdapter;
import org.onosproject.store.service.DistributedSetBuilder;
import org.onosproject.store.service.MapEvent;
import org.onosproject.store.service.MapEventListener;
import org.onosproject.store.service.SetEventListener;
import org.onosproject.store.service.StorageServiceAdapter;
import org.onosproject.store.service.Versioned;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.function.BiFunction;

import static com.google.common.base.Preconditions.checkState;
import static org.onosproject.cluster.NodeId.nodeId;
import static org.onosproject.net.NetTestTools.PID;
import static org.opencord.maclearner.app.impl.MacLearnerManagerTest.AGG_DEVICE_ID;
import static org.opencord.maclearner.app.impl.MacLearnerManagerTest.AGG_OLT_PORT;
import static org.opencord.maclearner.app.impl.MacLearnerManagerTest.CLIENT_CP;
import static org.opencord.maclearner.app.impl.MacLearnerManagerTest.OLT_DEVICE_ID;
import static org.opencord.maclearner.app.impl.MacLearnerManagerTest.OLT_NNI_PORT;

/**
 * Mac Learner mock services class.
 */
public abstract class TestBaseMacLearner {

    protected static final String C1 = "C1";
    protected static final String C2 = "C2";
    protected static final String C3 = "C3";

    protected static final NodeId CNID_1 = nodeId(C1);
    protected static final NodeId CNID_2 = nodeId(C2);
    protected static final NodeId CNID_3 = nodeId(C3);

    protected static final ControllerNode CNODE_1 = new DefaultControllerNode(CNID_1, "10.0.0.1");
    protected static final ControllerNode CNODE_2 = new DefaultControllerNode(CNID_2, "10.0.0.2");
    protected static final ControllerNode CNODE_3 = new DefaultControllerNode(CNID_3, "10.0.0.3");

    private static final Ip4Address SERVER_IP = Ip4Address.valueOf("10.0.3.253");
    private static final Ip4Address INTERFACE_IP = Ip4Address.valueOf("10.0.3.254");

    protected MacLearnerManager macLearnerManager;
    protected ApplicationId appId;
    protected HostLearningConfig hostLearningConfig;

    protected ComponentConfigService componentConfigService = new MockComponentConfigService();
    protected MockCoreService coreService = new MockCoreService();
    protected MockStorageService storageService = new MockStorageService();
    protected MockPacketService packetService = new MockPacketService();
    protected MockClusterService clusterService = new MockClusterService();
    protected MockDeviceService deviceService = new MockDeviceService();
    protected MockTopologyService topologyService = new MockTopologyService();
    protected MockLinkService linkService = new MockLinkService();
    protected MacLearnerHostProvider macLearnerHostProvider = new MacLearnerHostProvider();
    protected MockHostService hostService = new MockHostService(Sets.newHashSet());

    public void setUpApp() throws IOException {
        macLearnerManager = new MacLearnerManager();
        macLearnerManager.componentConfigService = this.componentConfigService;
        macLearnerManager.coreService = this.coreService;
        macLearnerManager.storageService = this.storageService;
        macLearnerManager.packetService = this.packetService;
        macLearnerManager.clusterService = this.clusterService;
        macLearnerManager.deviceService = this.deviceService;
        macLearnerManager.topologyService = this.topologyService;
        macLearnerManager.linkService = this.linkService;
        hostLearningConfig = new HostLearningConfig();
        InputStream jsonStream = HostLearningConfigTest.class
                .getResourceAsStream("/host-learning-config.json");

        ConnectPoint subject = CLIENT_CP;
        String key = CoreService.CORE_APP_NAME;
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode = mapper.readTree(jsonStream);
        ConfigApplyDelegate delegate = new MockDelegate();

        hostLearningConfig = new HostLearningConfig();
        hostLearningConfig.init(subject, key, jsonNode, mapper, delegate);
        macLearnerHostProvider.providerService = new MockHostProviderService(macLearnerHostProvider);
        macLearnerManager.hostLocService = this.macLearnerHostProvider;
        injectEventDispatcher(macLearnerManager, new MockEventDispatcher());
        appId = macLearnerManager.coreService.registerApplication("org.opencord.maclearner");

        macLearnerManager.activate();
    }

    private class MockDelegate implements ConfigApplyDelegate {
        @Override
        public void onApply(Config config) {
        }
    }

    /**
     * Mocks an instance of {@link ApplicationId} so that the application
     * component under test can query and use its application ID.
     */
    private static final class MockApplicationId implements ApplicationId {

        private final short id;
        private final String name;

        public MockApplicationId(short id, String name) {
            this.id = id;
            this.name = name;
        }

        @Override
        public short id() {
            return id;
        }

        @Override
        public String name() {
            return name;
        }
    }

    private static final class MockComponentConfigService extends ComponentConfigAdapter {

    }

    /**
     * Mocks the core services of ONOS so that the application under test can
     * register and query application IDs.
     */
    private static final class MockCoreService extends CoreServiceAdapter {

        private List<ApplicationId> idList = Lists.newArrayList();
        private Map<String, ApplicationId> idMap = Maps.newHashMap();

        @Override
        public ApplicationId getAppId(Short id) {
            if (id >= idList.size()) {
                return null;
            }
            return idList.get(id);
        }

        @Override
        public ApplicationId getAppId(String name) {
            return idMap.get(name);
        }

        @Override
        public ApplicationId registerApplication(String name) {
            ApplicationId appId = idMap.get(name);
            if (appId == null) {
                appId = new MockApplicationId((short) idList.size(), name);
                idList.add(appId);
                idMap.put(name, appId);
            }
            return appId;
        }

    }

    private static class MockClusterService extends ClusterServiceAdapter {
        private final Map<NodeId, ControllerNode> nodes = new HashMap<>();
        private final Map<NodeId, ControllerNode.State> states = new HashMap<>();

        MockClusterService() {
            nodes.put(CNODE_1.id(), CNODE_1);
            nodes.put(CNODE_2.id(), CNODE_2);
            nodes.put(CNODE_3.id(), CNODE_3);

            states.put(CNODE_1.id(), ControllerNode.State.READY);
            states.put(CNODE_2.id(), ControllerNode.State.ACTIVE);
            states.put(CNODE_3.id(), ControllerNode.State.ACTIVE);
        }

        @Override
        public Set<ControllerNode> getNodes() {
            return ImmutableSet.copyOf(nodes.values());
        }

        @Override
        public ControllerNode getNode(NodeId nodeId) {
            return nodes.get(nodeId);
        }

        @Override
        public ControllerNode.State getState(NodeId nodeId) {
            return states.get(nodeId);
        }
    }

    /**
     * Mocks the device service of ONOS so that the application under test can
     * register listeners.
     */
    protected static class MockHostService extends HostServiceAdapter {
        private Set<Host> hosts;

        MockHostService(Set<Host> hosts) {
            this.hosts = ImmutableSet.copyOf(hosts);
        }

        @Override
        public Set<Host> getHosts() {
            return hosts;
        }

        @Override
        public Host getHost(HostId hostId) {
            return hosts.stream().filter(host -> hostId.equals(host.id())).findFirst().orElse(null);
        }
    }

    /**
     * Mocks the device service of ONOS so that the application under test can
     * register listeners.
     */
    private static class MockDeviceService extends DeviceServiceAdapter {

        private List<DeviceListener> listeners = Lists.newArrayList();

        @Override
        public Device getDevice(DeviceId deviceId) {
            if (deviceId.equals(OLT_DEVICE_ID)) {
                return new DefaultDevice(null, OLT_DEVICE_ID, Device.Type.SWITCH,
                        "VOLTHA Project", "open_pon", "open_pon",
                        "BBSIM_OLT_1", new ChassisId("a0a0a0a0a01"));
            } else {
                return null;
            }
        }

        @Override
        public void addListener(DeviceListener listener) {
            listeners.add(listener);
        }

        @Override
        public void removeListener(DeviceListener listener) {
            listeners.remove(listener);
        }
    }

    /**
     * Mocks the topology service of ONOS so that the application under test can
     * check fake topology.
     */
    private static class MockTopologyService extends TopologyServiceAdapter {

        private final Topology topology = new MockTopology();

        @Override
        public Topology currentTopology() {
            return topology;
        }

        @Override
        public boolean isInfrastructure(Topology topology, ConnectPoint connectPoint) {
            return false;
        }
    }

    private static class MockTopology implements Topology {
        @Override
        public long time() {
            return 11111L;
        }

        @Override
        public long creationTime() {
            return 22222L;
        }

        @Override
        public long computeCost() {
            return 0;
        }

        @Override
        public int clusterCount() {
            return 2;
        }

        @Override
        public int deviceCount() {
            return 6;
        }

        @Override
        public int linkCount() {
            return 4;
        }

        @Override
        public ProviderId providerId() {
            return ProviderId.NONE;
        }
    }

    /**
     * Mocks the storage service of ONOS so that the application under test can
     * use consistent maps.
     */
    private static class MockStorageService extends StorageServiceAdapter {

        @Override
        public <K, V> ConsistentMapBuilder<K, V> consistentMapBuilder() {
            ConsistentMapBuilder<K, V> builder = new ConsistentMapBuilder<K, V>() {
                @Override
                public AsyncConsistentMap<K, V> buildAsyncMap() {
                    return null;
                }

                @Override
                public ConsistentMap<K, V> build() {
                    return new TestConsistentMap<>();
                }
            };

            return builder;
        }

        @Override
        public <E> DistributedSetBuilder<E> setBuilder() {
            DistributedSetBuilder<E> builder = new DistributedSetBuilder<E>() {
                @Override
                public AsyncDistributedSet<E> build() {
                    return new DistributedSetAdapter<E>() {
                        @Override
                        public DistributedSet<E> asDistributedSet() {
                            return new TestDistributedSet<>();
                        }
                    };
                }
            };

            return builder;
        }

        @Override
        public AtomicCounter getAtomicCounter(String name) {
            return new MockAtomicCounter();
        }

        // Mock ConsistentMap that behaves as a HashMap
        class TestConsistentMap<K, V> extends ConsistentMapAdapter<K, V> {
            private Map<K, Versioned<V>> map = new HashMap<>();
            private Map<MapEventListener<K, V>, Executor> listeners = new HashMap<>();

            public void notifyListeners(MapEvent<K, V> event) {
                listeners.forEach((c, e) -> e.execute(() -> c.event(event)));
            }

            @Override
            public int size() {
                return map.size();
            }

            @Override
            public Versioned<V> put(K key, V value) {
                Versioned<V> oldValue = map.get(key);
                Versioned<V> newValue = new Versioned<>(value, oldValue == null ? 0 : oldValue.version() + 1);
                map.put(key, newValue);
                notifyListeners(new MapEvent<>(name(), key, newValue, oldValue));
                return newValue;
            }

            @Override
            public Versioned<V> get(K key) {
                return map.get(key);
            }

            @Override
            public Versioned<V> remove(K key) {
                Versioned<V> oldValue = map.remove(key);
                notifyListeners(new MapEvent<>(name(), key, oldValue, null));
                return oldValue;
            }

            @Override
            public Versioned<V> computeIfPresent(K key,
                                                 BiFunction<? super K, ? super V, ? extends V> remappingFunction) {
                Versioned<V> oldValue = map.get(key);
                Versioned<V> newValue = new Versioned<>(remappingFunction.apply(key, oldValue.value()),
                        oldValue == null ? 0 : oldValue.version() + 1);
                map.put(key, newValue);
                notifyListeners(new MapEvent<>(name(), key, newValue, oldValue));
                return newValue;
            }

            @Override
            public Set<Map.Entry<K, Versioned<V>>> entrySet() {
                return map.entrySet();
            }

            @Override
            public Set<K> keySet() {
                return map.keySet();
            }

            @Override
            public Collection<Versioned<V>> values() {
                return map.values();
            }

            @Override
            public void clear() {
                map.clear();
            }

            @Override
            public void addListener(MapEventListener<K, V> listener, Executor executor) {
                listeners.put(listener, executor);
            }

            @Override
            public void removeListener(MapEventListener<K, V> listener) {
                listeners.remove(listener);
            }
        }

        // Mock DistributedSet that behaves as a HashSet
        class TestDistributedSet<E> extends HashSet<E> implements DistributedSet<E> {

            @Override
            public void addListener(SetEventListener<E> listener) {
            }

            @Override
            public void removeListener(SetEventListener<E> listener) {
            }

            @Override
            public String name() {
                return null;
            }

            @Override
            public Type primitiveType() {
                return null;
            }
        }
    }

    private static class MockAtomicCounter implements AtomicCounter {
        long id = 0;

        @Override
        public long incrementAndGet() {
            return ++id;
        }

        @Override
        public long getAndIncrement() {
            return id++;
        }

        @Override
        public long getAndAdd(long delta) {
            long oldId = id;
            id += delta;
            return oldId;
        }

        @Override
        public long addAndGet(long delta) {
            id += delta;
            return id;
        }

        @Override
        public void set(long value) {
            id = value;
        }

        @Override
        public boolean compareAndSet(long expectedValue, long updateValue) {
            if (id == expectedValue) {
                id = updateValue;
                return true;
            } else {
                return false;
            }
        }

        @Override
        public long get() {
            return id;
        }

        @Override
        public String name() {
            return "MockAtomicCounter";
        }
    }

    /**
     * Mocks the packet service of ONOS so that the application under test can
     * observe network packets.
     */
    public static class MockPacketService extends PacketServiceAdapter {
        Set<PacketProcessor> packetProcessors = Sets.newHashSet();
        OutboundPacket emittedPacket;

        @Override
        public void addProcessor(PacketProcessor processor, int priority) {
            packetProcessors.add(processor);
        }

        public void processPacket(PacketContext packetContext) {
            packetProcessors.forEach(p -> p.process(packetContext));
        }

        @Override
        public void emit(OutboundPacket packet) {
            this.emittedPacket = packet;
        }
    }

    /**
     * Mocks the link service of ONOS so that the application under test can
     * observe links.
     */
    public static class MockLinkService extends LinkServiceAdapter {

        Link link = DefaultLink.builder()
                .type(Link.Type.DIRECT)
                .providerId(PID)
                .src(new ConnectPoint(OLT_DEVICE_ID, OLT_NNI_PORT))
                .dst(new ConnectPoint(AGG_DEVICE_ID, AGG_OLT_PORT)).build();

        @Override
        public Set<Link> getDeviceLinks(DeviceId deviceId) {
            return Sets.newHashSet(link);
        }
    }

    /**
     * Implements event delivery system that delivers events synchronously, or
     * in-line with the post method invocation.
     */
    public static class MockEventDispatcher extends DefaultEventSinkRegistry
            implements EventDeliveryService {

        @Override
        @SuppressWarnings("unchecked")
        public synchronized void post(Event event) {
            EventSink sink = getSink(event.getClass());
            checkState(sink != null, "No sink for event %s", event);
            sink.process(event);
        }

        @Override
        public void setDispatchTimeLimit(long millis) {
        }

        @Override
        public long getDispatchTimeLimit() {
            return 0;
        }
    }

    public static void injectEventDispatcher(Object manager, EventDeliveryService svc) {
        Class mc = manager.getClass();
        Field[] var3 = mc.getSuperclass().getDeclaredFields();

        for (Field f : var3) {
            if (f.getType().equals(EventDeliveryService.class)) {
                try {
                    TestUtils.setField(manager, f.getName(), svc);
                    break;
                } catch (TestUtils.TestUtilsException var8) {
                    throw new IllegalArgumentException("Unable to inject reference", var8);
                }
            }
        }
    }

    /**
     * Mock HostProviderService.
     */
    private class MockHostProviderService
            extends AbstractProviderService<HostProvider>
            implements HostProviderService {
        private HostId hostId = null;
        private HostDescription hostDescription = null;
        private String event = null;

        public MockHostProviderService(HostProvider provider) {
            super(provider);
        }

        @Override
        public void hostDetected(HostId hostId, HostDescription hostDescription, boolean replaceIps) {
            this.hostId = hostId;
            this.hostDescription = hostDescription;
            this.event = "hostDetected";
            Set<Host> previousHosts = Sets.newHashSet(hostService.getHosts());
            previousHosts.add(new DefaultHost(provider().id(), hostId, hostDescription.hwAddress(),
                    hostDescription.vlan(), hostDescription.locations(), hostDescription.auxLocations(),
                    hostDescription.ipAddress(), VlanId.NONE,
                    EthType.EtherType.UNKNOWN.ethType(), false, false));
            hostService = new MockHostService(previousHosts);
        }

        @Override
        public void hostVanished(HostId hostId) {
            this.hostId = hostId;
            this.event = "hostVanished";
            Set<Host> previousHosts = Sets.newHashSet(hostService.getHosts());
            Host removedHost = hostService.getHost(hostId);
            previousHosts.remove(removedHost);
            hostService = new MockHostService(previousHosts);
        }

        @Override
        public void removeIpFromHost(HostId hostId, IpAddress ipAddress) {
            // not implemented
        }

        @Override
        public void removeLocationFromHost(HostId hostId, HostLocation location) {
            // not implemented
        }

        public void clear() {
            this.hostId = null;
            this.hostDescription = null;
            this.event = null;
        }
    }

    /**
     * Generates DHCP REQUEST packet.
     */
    protected static class TestDhcpRequestPacketContext extends PacketContextAdapter {

        private InboundPacket inPacket;

        public TestDhcpRequestPacketContext(MacAddress clientMac, VlanId vlanId,
                                            VlanId qinqQVid,
                                            ConnectPoint clientCp) {
            super(0, null, null, false);
            byte[] dhcpMsgType = new byte[1];
            dhcpMsgType[0] = (byte) DHCP.MsgType.DHCPREQUEST.getValue();

            DhcpOption dhcpOption = new DhcpOption();
            dhcpOption.setCode(DHCP.DHCPOptionCode.OptionCode_MessageType.getValue());
            dhcpOption.setData(dhcpMsgType);
            dhcpOption.setLength((byte) 1);
            DhcpOption endOption = new DhcpOption();
            endOption.setCode(DHCP.DHCPOptionCode.OptionCode_END.getValue());

            DHCP dhcp = new DHCP();
            dhcp.setHardwareType(DHCP.HWTYPE_ETHERNET);
            dhcp.setHardwareAddressLength((byte) 6);
            dhcp.setClientHardwareAddress(clientMac.toBytes());
            dhcp.setOptions(ImmutableList.of(dhcpOption, endOption));


            UDP udp = new UDP();
            udp.setPayload(dhcp);
            udp.setSourcePort(UDP.DHCP_CLIENT_PORT);
            udp.setDestinationPort(UDP.DHCP_SERVER_PORT);

            IPv4 ipv4 = new IPv4();
            ipv4.setPayload(udp);
            ipv4.setDestinationAddress(SERVER_IP.toInt());
            ipv4.setSourceAddress(INTERFACE_IP.toInt());

            Ethernet eth = new Ethernet();
            eth.setEtherType(Ethernet.TYPE_IPV4)
                    .setVlanID(vlanId.toShort())
                    .setQinQVID(qinqQVid.toShort())
                    .setSourceMACAddress(clientMac)
                    .setDestinationMACAddress(MacAddress.BROADCAST)
                    .setPayload(ipv4);

            this.inPacket = new DefaultInboundPacket(clientCp, eth,
                    ByteBuffer.wrap(eth.serialize()));
        }

        @Override
        public InboundPacket inPacket() {
            return this.inPacket;
        }
    }

}
