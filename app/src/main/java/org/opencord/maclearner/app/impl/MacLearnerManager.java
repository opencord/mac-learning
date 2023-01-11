/*
 * Copyright 2017-2023 Open Networking Foundation (ONF) and the ONF Contributors
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

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import org.onlab.packet.EthType;
import org.onlab.packet.IpAddress;
import org.onlab.packet.VlanId;
import org.onlab.util.PredictableExecutor;
import org.onlab.util.Tools;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.cluster.ClusterEvent;
import org.onosproject.cluster.ClusterEventListener;
import org.onosproject.cluster.ClusterService;
import org.onosproject.cluster.ControllerNode;
import org.onosproject.cluster.LeadershipService;
import org.onosproject.cluster.NodeId;
import org.onosproject.core.ApplicationId;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Device;
import org.onosproject.net.ElementId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.HostLocation;
import org.onosproject.net.Link;
import org.onosproject.net.Port;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.topology.Topology;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.store.service.ConsistentMap;
import org.onosproject.store.service.StorageService;
import org.onosproject.store.service.Versioned;
import org.opencord.maclearner.api.DefaultMacLearner;
import org.opencord.maclearner.api.MacLearnerHostLocationService;
import org.opencord.maclearner.api.MacDeleteResult;
import org.opencord.maclearner.api.MacLearnerEvent;
import org.opencord.maclearner.api.MacLearnerKey;
import org.opencord.maclearner.api.MacLearnerListener;
import org.opencord.maclearner.api.MacLearnerProvider;
import org.opencord.maclearner.api.MacLearnerProviderService;
import org.opencord.maclearner.api.MacLearnerService;
import org.opencord.maclearner.api.MacLearnerValue;
import org.opencord.sadis.BaseInformationService;
import org.opencord.sadis.SadisService;
import org.opencord.sadis.SubscriberAndDeviceInformation;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.onlab.packet.DHCP;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.MacAddress;
import org.onlab.packet.UDP;
import org.onlab.packet.dhcp.DhcpOption;
import org.onlab.util.KryoNamespace;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.provider.AbstractListenerProviderRegistry;
import org.onosproject.net.provider.AbstractProviderService;
import org.onosproject.store.LogicalTimestamp;
import org.onosproject.store.serializers.KryoNamespaces;
import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.WallClockTimestamp;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Date;
import java.util.Dictionary;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static com.google.common.base.Strings.isNullOrEmpty;
import static java.util.stream.Collectors.toList;
import static org.onlab.packet.DHCP.DHCPOptionCode.OptionCode_MessageType;
import static org.onlab.util.Tools.groupedThreads;
import static org.opencord.maclearner.app.impl.OsgiPropertyConstants.AUTO_CLEAR_MAC_MAPPING;
import static org.opencord.maclearner.app.impl.OsgiPropertyConstants.AUTO_CLEAR_MAC_MAPPING_DEFAULT;
import static org.opencord.maclearner.app.impl.OsgiPropertyConstants.CACHE_DURATION_DEFAULT;
import static org.opencord.maclearner.app.impl.OsgiPropertyConstants.CACHE_DURATION;
import static org.opencord.maclearner.app.impl.OsgiPropertyConstants.ENABLE_DHCP_FORWARD;
import static org.opencord.maclearner.app.impl.OsgiPropertyConstants.ENABLE_DHCP_FORWARD_DEFAULT;
import static org.osgi.service.component.annotations.ReferenceCardinality.MANDATORY;

/**
 * Mac Learner Service implementation.
 */
@Component(immediate = true,
        property = {
                CACHE_DURATION + ":Integer=" + CACHE_DURATION_DEFAULT,
                AUTO_CLEAR_MAC_MAPPING + ":Boolean=" + AUTO_CLEAR_MAC_MAPPING_DEFAULT,
                ENABLE_DHCP_FORWARD + ":Boolean=" + ENABLE_DHCP_FORWARD_DEFAULT
        },
        service = MacLearnerService.class
)
public class MacLearnerManager
        extends AbstractListenerProviderRegistry<MacLearnerEvent, MacLearnerListener,
        MacLearnerProvider, MacLearnerProviderService>
        implements MacLearnerService {

    private static final String MAC_LEARNER_APP = "org.opencord.maclearner";
    private static final String MAC_LEARNER = "maclearner";
    private static final String OLT_MANUFACTURER_KEY = "VOLTHA";
    private ApplicationId appId;

    private final ScheduledExecutorService scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
    private ScheduledFuture scheduledFuture;

    private final Logger log = LoggerFactory.getLogger(getClass());

    protected BaseInformationService<SubscriberAndDeviceInformation> subsService;

    @Reference(cardinality = ReferenceCardinality.OPTIONAL,
            bind = "bindSadisService",
            unbind = "unbindSadisService",
            policy = ReferencePolicy.DYNAMIC)
    protected volatile SadisService sadisService;

    @Reference(cardinality = MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = MANDATORY)
    protected ClusterService clusterService;

    @Reference(cardinality = MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = MANDATORY)
    protected LeadershipService leadershipService;

    @Reference(cardinality = MANDATORY)
    protected MastershipService mastershipService;

    @Reference(cardinality = MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = MANDATORY)
    protected StorageService storageService;

    @Reference(cardinality = MANDATORY)
    protected TopologyService topologyService;

    @Reference(cardinality = MANDATORY)
    protected ComponentConfigService componentConfigService;

    @Reference(cardinality = MANDATORY)
    protected MacLearnerHostLocationService hostLocService;

    @Reference(cardinality = MANDATORY)
    protected LinkService linkService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    private final MacLearnerPacketProcessor macLearnerPacketProcessor =
            new MacLearnerPacketProcessor();

    private final DeviceListener deviceListener = new InternalDeviceListener();
    private final ClusterEventListener clusterListener = new InternalClusterListener();

    private ConsistentHasher hasher;
    public static final int HASH_WEIGHT = 10;

    /**
     * Enables Dhcp forwarding.
     */
    protected boolean enableDhcpForward = ENABLE_DHCP_FORWARD_DEFAULT;

    /**
     * Minimum duration of mapping, mapping can be exist until 2*cacheDuration because of cleanerTimer fixed rate.
     */
    protected int cacheDurationSec = CACHE_DURATION_DEFAULT;

    /**
     * Removes mappings from MAC Address Map for removed events.
     */
    protected boolean autoClearMacMapping = AUTO_CLEAR_MAC_MAPPING_DEFAULT;

    private ConsistentMap<DeviceId, Set<PortNumber>> ignoredPortsMap;
    private ConsistentMap<MacLearnerKey, MacLearnerValue> macAddressMap;

    protected ExecutorService eventExecutor;
    // Packet workers - 0 will leverage available processors
    private static final int DEFAULT_THREADS = 0;
    private PredictableExecutor packetWorkers;

    @Activate
    public void activate() {
        eventExecutor = Executors.newFixedThreadPool(5, groupedThreads("onos/maclearner",
                "events-%d", log));
        appId = coreService.registerApplication(MAC_LEARNER_APP);
        componentConfigService.registerProperties(getClass());
        eventDispatcher.addSink(MacLearnerEvent.class, listenerRegistry);
        macAddressMap = storageService.<MacLearnerKey, MacLearnerValue>consistentMapBuilder()
                .withName(MAC_LEARNER)
                .withSerializer(createSerializer())
                .withApplicationId(appId)
                .build();
        ignoredPortsMap = storageService
                .<DeviceId, Set<PortNumber>>consistentMapBuilder()
                .withName("maclearner-ignored")
                .withSerializer(createSerializer())
                .withApplicationId(appId)
                .build();
        packetWorkers = new PredictableExecutor(DEFAULT_THREADS,
                                                groupedThreads("onos/mac-learner-host-loc-provider",
                                                                                "packet-worker-%d", log));
        //mac learner must process the packet before director processors
        packetService.addProcessor(macLearnerPacketProcessor,
                PacketProcessor.advisor(2));
        List<NodeId> readyNodes = clusterService.getNodes().stream()
                .filter(c -> clusterService.getState(c.id()) == ControllerNode.State.READY)
                .map(ControllerNode::id)
                .collect(toList());
        hasher = new ConsistentHasher(readyNodes, HASH_WEIGHT);
        clusterService.addListener(clusterListener);
        deviceService.addListener(deviceListener);
        createSchedulerForClearMacMappings();

        if (sadisService != null) {
            subsService = sadisService.getSubscriberInfoService();
        } else {
            log.warn("Sadis is not running");
        }

        log.info("{} is started.", getClass().getSimpleName());
    }

    private Serializer createSerializer() {
        return Serializer.using(KryoNamespace.newBuilder()
                .register(KryoNamespace.newBuilder().build(MAC_LEARNER))
                // not so robust way to avoid collision with other
                // user supplied registrations
                .nextId(KryoNamespaces.BEGIN_USER_CUSTOM_ID + 100)
                .register(KryoNamespaces.BASIC)
                .register(LogicalTimestamp.class)
                .register(WallClockTimestamp.class)
                .register(MacLearnerKey.class)
                .register(MacLearnerValue.class)
                .register(DeviceId.class)
                .register(URI.class)
                .register(PortNumber.class)
                .register(VlanId.class)
                .register(MacAddress.class)
                .build(MAC_LEARNER + "-ecmap"));
    }

    private void createSchedulerForClearMacMappings() {
        scheduledFuture = scheduledExecutorService.scheduleAtFixedRate(this::clearExpiredMacMappings,
                0,
                cacheDurationSec,
                TimeUnit.SECONDS);
    }

    private void clearExpiredMacMappings() {
        Date curDate = new Date();
        for (Map.Entry<MacLearnerKey, Versioned<MacLearnerValue>> entry : macAddressMap.entrySet()) {
            if (!isLocalLeader(entry.getKey().getDeviceId())) {
                continue;
            }
            if (curDate.getTime() - entry.getValue().value().getTimestamp() > cacheDurationSec * 1000) {
                removeFromMacAddressMap(entry.getKey(), false);
            }
        }
    }

    /**
     * Determines if this instance should handle this device based on
     * consistent hashing.
     *
     * @param deviceId device ID
     * @return true if this instance should handle the device, otherwise false
     */
    public boolean isLocalLeader(DeviceId deviceId) {
        if (deviceService.isAvailable(deviceId)) {
            return mastershipService.isLocalMaster(deviceId);
        } else {
            // Fallback with Leadership service - device id is used as topic
            NodeId leader = leadershipService.runForLeadership(
                    deviceId.toString()).leaderNodeId();
            // Verify if this node is the leader
            return clusterService.getLocalNode().id().equals(leader);
        }
    }
    protected void bindSadisService(SadisService service) {
        this.subsService = service.getSubscriberInfoService();
        log.info("Sadis service is loaded");
    }

    protected void unbindSadisService(SadisService service) {
        this.subsService = null;
        log.info("Sadis service is unloaded");
    }

    @Deactivate
    public void deactivate() {
        if (scheduledFuture != null) {
            scheduledFuture.cancel(true);
        }
        packetService.removeProcessor(macLearnerPacketProcessor);
        clusterService.removeListener(clusterListener);
        deviceService.removeListener(deviceListener);
        eventDispatcher.removeSink(MacLearnerEvent.class);
        packetWorkers.shutdown();
        if (eventExecutor != null) {
            eventExecutor.shutdown();
        }
        componentConfigService.unregisterProperties(getClass(), false);
        log.info("{} is stopped.", getClass().getSimpleName());
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();

        String cacheDuration = Tools.get(properties, CACHE_DURATION);
        if (!isNullOrEmpty(cacheDuration)) {
            int cacheDur = Integer.parseInt(cacheDuration.trim());
            if (cacheDurationSec != cacheDur) {
                setMacMappingCacheDuration(cacheDur);
            }
        }

        Boolean o = Tools.isPropertyEnabled(properties, ENABLE_DHCP_FORWARD);
        if (o != null) {
            if (o != enableDhcpForward) {
                log.info("Changing enableDhcpForward to: {} from {}", o, enableDhcpForward);
                enableDhcpForward = o;
            }
        }

        o = Tools.isPropertyEnabled(properties, AUTO_CLEAR_MAC_MAPPING);
        if (o != null) {
            if (o != autoClearMacMapping) {
                log.info("Changing autoClearMacMapping to: {} from {}", o, autoClearMacMapping);
                autoClearMacMapping = o;
            }
        }
    }

    private Integer setMacMappingCacheDuration(Integer second) {
        if (cacheDurationSec == second) {
            log.info("Cache duration already: {}", second);
            return second;
        }
        log.info("Changing cache duration to: {} second from {} second...", second, cacheDurationSec);
        this.cacheDurationSec = second;
        if (scheduledFuture != null) {
            scheduledFuture.cancel(false);
        }
        createSchedulerForClearMacMappings();
        return cacheDurationSec;
    }

    @Override
    public void addPortToIgnore(DeviceId deviceId, PortNumber portNumber) {
        log.info("Adding ignore port: {} {}", deviceId, portNumber);
        Set<PortNumber> updatedPorts = Sets.newHashSet();
        Versioned<Set<PortNumber>> storedPorts = ignoredPortsMap.get(deviceId);
        if (storedPorts == null || !storedPorts.value().contains(portNumber)) {
            if (storedPorts != null) {
                updatedPorts.addAll(storedPorts.value());
            }
            updatedPorts.add(portNumber);
            ignoredPortsMap.put(deviceId, updatedPorts);
            log.info("Port:{} of device: {} is added to ignoredPortsMap.", portNumber, deviceId);
            deleteMacMappings(deviceId, portNumber);
        } else {
            log.warn("Port:{} of device: {} is already ignored.", portNumber, deviceId);
        }
    }

    @Override
    public void removeFromIgnoredPorts(DeviceId deviceId, PortNumber portNumber) {
        log.info("Removing ignore port: {} {}", deviceId, portNumber);
        Versioned<Set<PortNumber>> storedPorts = ignoredPortsMap.get(deviceId);
        if (storedPorts != null && storedPorts.value().contains(portNumber)) {
            if (storedPorts.value().size() == 1) {
                ignoredPortsMap.remove(deviceId);
            } else {
                Set<PortNumber> updatedPorts = Sets.newHashSet();
                updatedPorts.addAll(storedPorts.value());
                updatedPorts.remove(portNumber);
                ignoredPortsMap.put(deviceId, updatedPorts);
            }
            log.info("Port:{} of device: {} is removed ignoredPortsMap.", portNumber, deviceId);
        } else {
            log.warn("Port:{} of device: {} is not found in ignoredPortsMap.", portNumber, deviceId);
        }
    }

    @Override
    public ImmutableMap<MacLearnerKey, MacAddress> getAllMappings() {
        log.info("Getting all MAC Mappings");
        Map<MacLearnerKey, MacAddress> immutableMap = Maps.newHashMap();
        macAddressMap.entrySet().forEach(entry ->
                immutableMap.put(entry.getKey(),
                        entry.getValue() != null ? entry.getValue().value().getMacAddress() : null));
        return ImmutableMap.copyOf(immutableMap);
    }

    @Override
    public Optional<MacAddress> getMacMapping(DeviceId deviceId, PortNumber portNumber, VlanId vlanId) {
        log.info("Getting MAC mapping for: {} {} {}", deviceId, portNumber, vlanId);
        Versioned<MacLearnerValue> value = macAddressMap.get(new MacLearnerKey(deviceId, portNumber, vlanId));
        return value != null ? Optional.ofNullable(value.value().getMacAddress()) : Optional.empty();
    }

    @Override
    public MacDeleteResult deleteMacMapping(DeviceId deviceId, PortNumber portNumber, VlanId vlanId) {
        log.info("Deleting MAC mapping for: {} {} {}", deviceId, portNumber, vlanId);
        MacLearnerKey key = new MacLearnerKey(deviceId, portNumber, vlanId);
        return removeFromMacAddressMap(key, true);
    }

    @Override
    public boolean deleteMacMappings(DeviceId deviceId, PortNumber portNumber) {
        log.info("Deleting MAC mappings for: {} {}", deviceId, portNumber);
        Set<Map.Entry<MacLearnerKey, Versioned<MacLearnerValue>>> entriesToDelete = macAddressMap.entrySet().stream()
                .filter(entry -> entry.getKey().getDeviceId().equals(deviceId) &&
                        entry.getKey().getPortNumber().equals(portNumber))
                .collect(Collectors.toSet());
        if (entriesToDelete.isEmpty()) {
            log.warn("MAC mapping not found for deviceId: {} and portNumber: {}", deviceId, portNumber);
            return false;
        }
        entriesToDelete.forEach(e -> removeFromMacAddressMap(e.getKey(), true));
        return true;
    }

    @Override
    public boolean deleteMacMappings(DeviceId deviceId) {
        log.info("Deleting MAC mappings for: {}", deviceId);
        Set<Map.Entry<MacLearnerKey, Versioned<MacLearnerValue>>> entriesToDelete = macAddressMap.entrySet().stream()
                .filter(entry -> entry.getKey().getDeviceId().equals(deviceId))
                .collect(Collectors.toSet());
        if (entriesToDelete.isEmpty()) {
            log.warn("MAC mapping not found for deviceId: {}", deviceId);
            return false;
        }
        entriesToDelete.forEach(e -> removeFromMacAddressMap(e.getKey(), true));
        return true;
    }

    @Override
    public ImmutableSet<DeviceId> getMappedDevices() {
        Set<DeviceId> deviceIds = Sets.newHashSet();
        for (Map.Entry<MacLearnerKey, MacAddress> entry : getAllMappings().entrySet()) {
            deviceIds.add(entry.getKey().getDeviceId());
        }
        return ImmutableSet.copyOf(deviceIds);
    }

    @Override
    public ImmutableSet<PortNumber> getMappedPorts() {
        Set<PortNumber> portNumbers = Sets.newHashSet();
        for (Map.Entry<MacLearnerKey, MacAddress> entry : getAllMappings().entrySet()) {
            portNumbers.add(entry.getKey().getPortNumber());
        }
        return ImmutableSet.copyOf(portNumbers);
    }

    @Override
    public ImmutableMap<DeviceId, Set<PortNumber>> getIgnoredPorts() {
        log.info("Getting ignored ports");
        Map<DeviceId, Set<PortNumber>> immutableMap = Maps.newHashMap();
        ignoredPortsMap.forEach(entry -> immutableMap.put(entry.getKey(),
                entry.getValue() != null ? entry.getValue().value() : Sets.newHashSet()));
        return ImmutableMap.copyOf(immutableMap);
    }

    @Override
    protected MacLearnerProviderService createProviderService(MacLearnerProvider provider) {
        return new InternalMacLearnerProviderService(provider);
    }

    private static class InternalMacLearnerProviderService extends AbstractProviderService<MacLearnerProvider>
            implements MacLearnerProviderService {

        InternalMacLearnerProviderService(MacLearnerProvider provider) {
            super(provider);
        }
    }

    private void sendMacLearnerEvent(MacLearnerEvent.Type type, DeviceId deviceId,
                                     PortNumber portNumber, VlanId vlanId, MacAddress macAddress) {
        log.info("Sending MAC Learner Event: type: {} deviceId: {} portNumber: {} vlanId: {} macAddress: {}",
                type, deviceId, portNumber, vlanId.toShort(), macAddress);
        DefaultMacLearner macLearner = new DefaultMacLearner(deviceId, portNumber, vlanId, macAddress);
        MacLearnerEvent macLearnerEvent = new MacLearnerEvent(type, macLearner);
        post(macLearnerEvent);
    }

    private boolean isOltDevice(Device device) {
        return device.manufacturer().contains(OLT_MANUFACTURER_KEY);
    }

    private class MacLearnerPacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            packetWorkers.submit(() -> processPacketInternal(context));
        }

        private void processPacketInternal(PacketContext context) {
            // process the packet and get the payload
            Ethernet packet = context.inPacket().parsed();

            if (packet == null) {
                log.warn("Packet is null");
                return;
            }

            ConnectPoint cp = context.inPacket().receivedFrom();
            DeviceId deviceId = cp.deviceId();
            PortNumber sourcePort = cp.port();
            MacAddress srcMac = packet.getSourceMAC();
            MacAddress dstMac = packet.getDestinationMAC();

            Device device = deviceService.getDevice(deviceId);
            if (!isOltDevice(device)) { // not handle non OLT device packets
                log.debug("Packet received from non-OLT device: {}. Returning.", deviceId);
                return;
            }

            if (srcMac.isBroadcast() || srcMac.isMulticast()) {
                log.debug("Broadcast or multicast packet received from: {}. Returning.", cp);
                return;
            }

            // Ignore location probes
            if (dstMac.isOnos() && !MacAddress.NONE.equals(dstMac)) {
                log.debug("Location probe. cp: {}", cp);
                return;
            }

            // If this arrived on control port, bail out.
            if (cp.port().isLogical()) {
                log.debug("Packet received from logical port: {}", cp);
                return;
            }

            // If this is not an edge port, bail out.
            Topology topology = topologyService.currentTopology();
            if (topologyService.isInfrastructure(topology, cp)) {
                log.debug("Packet received from non-edge port: {}", cp);
                return;
            }

            VlanId vlan = VlanId.vlanId(packet.getVlanID());
            VlanId outerVlan = VlanId.vlanId(packet.getQinQVID());
            VlanId innerVlan = VlanId.NONE;
            EthType outerTpid = EthType.EtherType.UNKNOWN.ethType();
            // Set up values for double-tagged hosts
            if (outerVlan.toShort() != Ethernet.VLAN_UNTAGGED) {
                innerVlan = vlan;
                vlan = outerVlan;
                outerTpid = EthType.EtherType.lookup(packet.getQinQTPID()).ethType();
            }

            Versioned<Set<PortNumber>> ignoredPortsOfDevice = ignoredPortsMap.get(deviceId);
            if (ignoredPortsOfDevice != null && ignoredPortsOfDevice.value().contains(sourcePort)) {
                log.warn("Port Number: {} is in ignoredPortsMap. Returning", sourcePort);
                return;
            }

            if (packet.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipv4Packet = (IPv4) packet.getPayload();

                if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_UDP) {
                    UDP udpPacket = (UDP) ipv4Packet.getPayload();
                    int udpSourcePort = udpPacket.getSourcePort();
                    if ((udpSourcePort == UDP.DHCP_CLIENT_PORT) || (udpSourcePort == UDP.DHCP_SERVER_PORT)) {
                        // Update host location
                        HostLocation hloc = new HostLocation(cp, System.currentTimeMillis());
                        HostLocation auxLocation = null;
                        Optional<Link> optLink = linkService.getDeviceLinks(deviceId).stream().findFirst();
                        if (optLink.isPresent()) {
                            Link link = optLink.get();
                            auxLocation = !link.src().deviceId().equals(deviceId) ?
                                    new HostLocation(link.src(), System.currentTimeMillis()) :
                                    new HostLocation(link.dst(), System.currentTimeMillis());
                        } else {
                            log.debug("Link not found for device {}", deviceId);
                        }
                        hostLocService.createOrUpdateHost(HostId.hostId(packet.getSourceMAC(), vlan),
                                                          packet.getSourceMAC(), packet.getDestinationMAC(),
                                                          vlan, innerVlan, outerTpid,
                                                          hloc, auxLocation, null);
                        DHCP dhcpPayload = (DHCP) udpPacket.getPayload();
                        //This packet is dhcp.
                        processDhcpPacket(context, packet, dhcpPayload, sourcePort, deviceId, vlan);

                        if (enableDhcpForward) {
                            // Forward DHCP Packet to either uni or nni.
                            forwardDhcpPacket(packet, dhcpPayload, device, vlan);
                        }
                    }
                }
            }
        }

        /**
         * Returns the connectPoint which is the uplink port of the OLT.
         */
        private ConnectPoint getUplinkConnectPointOfOlt(DeviceId dId) {

            Device device = deviceService.getDevice(dId);

            if (device == null) {
                log.warn("Could not find device for device ID {}", dId);
                return null;
            }

            SubscriberAndDeviceInformation deviceInfo = subsService.get(device.serialNumber());
            if (deviceInfo != null) {
                log.debug("getUplinkConnectPointOfOlt DeviceId: {} devInfo: {}", dId, deviceInfo);
                PortNumber pNum = PortNumber.portNumber(deviceInfo.uplinkPort());
                Port port = deviceService.getPort(device.id(), pNum);
                if (port != null) {
                    return new ConnectPoint(device.id(), pNum);
                } else {
                    log.warn("Unable to find Port in deviceService for deice ID : {}, port : {}", dId, pNum);
                }
            } else {
                log.warn("Unable to find Sadis entry for device ID : {}, device serial : {}",
                        dId, device.serialNumber());
            }

            return null;
        }

        /***
         * Forwards the packet to uni port or nni port based on the DHCP source port.
         * Client DHCP packets are transparently forwarded to the nni port.
         * Server DHCP replies are forwared to the respective uni port based on the (mac,vlan) lookup
         */
        private void forwardDhcpPacket(Ethernet packet, DHCP dhcpPayload, Device device, VlanId vlan) {
            UDP udpPacket = (UDP) dhcpPayload.getParent();
            int udpSourcePort = udpPacket.getSourcePort();
            MacAddress clientMacAddress = MacAddress.valueOf(dhcpPayload.getClientHardwareAddress());

            ConnectPoint destinationCp = null;

            if (udpSourcePort == UDP.DHCP_CLIENT_PORT) {
                destinationCp = getUplinkConnectPointOfOlt(device.id());
            } else if (udpSourcePort == UDP.DHCP_SERVER_PORT) {
                Host host = hostService.getHost(HostId.hostId(clientMacAddress, vlan));

                ElementId elementId = host.location().elementId();
                PortNumber portNumber = host.location().port();

                destinationCp = new ConnectPoint(elementId, portNumber);
            }

            if (destinationCp == null) {
                log.error("No connect point to send msg to DHCP message");
                return;
            }

            if (log.isTraceEnabled()) {
                VlanId printVlan = VlanId.NONE;

                if (vlan != null) {
                    printVlan = vlan;
                }

                log.trace("Emitting : packet {}, with MAC {}, with VLAN {}, with connect point {}",
                        getDhcpPacketType(dhcpPayload), clientMacAddress, printVlan, destinationCp);
            }

            TrafficTreatment t = DefaultTrafficTreatment.builder()
                    .setOutput(destinationCp.port()).build();
            OutboundPacket o = new DefaultOutboundPacket(destinationCp
                    .deviceId(), t, ByteBuffer.wrap(packet.serialize()));
            packetService.emit(o);
        }

        //process the dhcp packet before forwarding
        private void processDhcpPacket(PacketContext context, Ethernet packet,
                                       DHCP dhcpPayload, PortNumber sourcePort, DeviceId deviceId, VlanId vlanId) {
            if (dhcpPayload == null) {
                log.warn("DHCP payload is null");
                return;
            }

            DHCP.MsgType incomingPacketType = getDhcpPacketType(dhcpPayload);

            if (incomingPacketType == null) {
                log.warn("Incoming packet type is null!");
                return;
            }

            log.info("Received DHCP Packet of type {} from {}",
                    incomingPacketType, context.inPacket().receivedFrom());

            if (incomingPacketType.equals(DHCP.MsgType.DHCPDISCOVER) ||
                    incomingPacketType.equals(DHCP.MsgType.DHCPREQUEST)) {
                addToMacAddressMap(deviceId, sourcePort, vlanId, packet.getSourceMAC());
            } else if (incomingPacketType.equals(DHCP.MsgType.DHCPACK)) {
                MacAddress hostMac = MacAddress.valueOf(dhcpPayload.getClientHardwareAddress());
                VlanId hostVlan = VlanId.vlanId(packet.getVlanID());
                HostId hostId = HostId.hostId(hostMac, hostVlan);
                hostLocService.updateHostIp(hostId, IpAddress.valueOf(dhcpPayload.getYourIPAddress()));
            }
        }

        // get type of the DHCP packet
        private DHCP.MsgType getDhcpPacketType(DHCP dhcpPayload) {

            for (DhcpOption option : dhcpPayload.getOptions()) {
                if (option.getCode() == OptionCode_MessageType.getValue()) {
                    byte[] data = option.getData();
                    return DHCP.MsgType.getType(data[0]);
                }
            }
            return null;
        }

        private void addToMacAddressMap(DeviceId deviceId, PortNumber portNumber,
                                        VlanId vlanId, MacAddress macAddress) {
            Versioned<MacLearnerValue> prevMacAddress =
                    macAddressMap.put(new MacLearnerKey(deviceId, portNumber, vlanId),
                            new MacLearnerValue(macAddress, new Date().getTime()));
            if (prevMacAddress != null && !prevMacAddress.value().getMacAddress().equals(macAddress)) {
                sendMacLearnerEvent(MacLearnerEvent.Type.REMOVED,
                        deviceId,
                        portNumber,
                        vlanId,
                        prevMacAddress.value().getMacAddress());
            }
            if (prevMacAddress == null || !prevMacAddress.value().getMacAddress().equals(macAddress)) {
                // Not sending event for already mapped
                log.info("Mapped MAC: {} for port: {} of deviceId: {} and vlanId: {}",
                        macAddress, portNumber, deviceId, vlanId);
                sendMacLearnerEvent(MacLearnerEvent.Type.ADDED, deviceId, portNumber, vlanId, macAddress);
            }
        }
    }

    private MacDeleteResult removeFromMacAddressMap(MacLearnerKey macLearnerKey, boolean vanishHost) {
        Versioned<MacLearnerValue> verMacAddress = macAddressMap.remove(macLearnerKey);
        if (verMacAddress != null) {
            log.info("Mapping removed. deviceId: {} portNumber: {} vlanId: {} macAddress: {}",
                    macLearnerKey.getDeviceId(), macLearnerKey.getPortNumber(),
                    verMacAddress.value(), verMacAddress.value().getMacAddress());
            sendMacLearnerEvent(MacLearnerEvent.Type.REMOVED,
                    macLearnerKey.getDeviceId(),
                    macLearnerKey.getPortNumber(),
                    macLearnerKey.getVlanId(),
                    verMacAddress.value().getMacAddress());
            if (vanishHost) {
                hostLocService.vanishHost(verMacAddress.value().getMacAddress(), macLearnerKey.getVlanId());
            }
            return MacDeleteResult.SUCCESSFUL;
        } else {
            log.warn("MAC not removed, because mapping not found for deviceId: {} and portNumber: {} and vlanId: {}",
                    macLearnerKey.getDeviceId(),
                    macLearnerKey.getPortNumber(),
                    macLearnerKey.getVlanId());
            return MacDeleteResult.NOT_EXIST;
        }
    }

    private class InternalDeviceListener implements DeviceListener {

        @Override
        public void event(DeviceEvent event) {
            eventExecutor.execute(() -> {
                Device device = event.subject();
                log.debug("Device event received: {}", event.type());
                switch (event.type()) {
                    case DEVICE_REMOVED:
                        if (autoClearMacMapping) {
                            deleteMacMappings(device.id());
                        }
                        break;
                    case PORT_REMOVED:
                        if (autoClearMacMapping) {
                            deleteMacMappings(device.id(), event.port().number());
                        }
                        break;
                    default:
                        log.debug("Unhandled device event for Mac Learner: {}", event.type());
                }
            });
        }

        @Override
        public boolean isRelevant(DeviceEvent event) {
             boolean master = isLocalLeader(event.subject().id());
             if (log.isDebugEnabled() && master) {
                 log.debug("Master for {}, handling event {}", event.subject().id(), event);
             }
             return master;
        }

    }

    private class InternalClusterListener implements ClusterEventListener {
        @Override
        public void event(ClusterEvent event) {
            if (event.type() == ClusterEvent.Type.INSTANCE_READY) {
                hasher.addServer(event.subject().id());
            }
            if (event.type() == ClusterEvent.Type.INSTANCE_DEACTIVATED) {
                hasher.removeServer(event.subject().id());
            }
        }
    }

}
