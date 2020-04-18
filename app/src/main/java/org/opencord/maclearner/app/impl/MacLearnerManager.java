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

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import org.onlab.packet.VlanId;
import org.onlab.util.Tools;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.store.service.ConsistentMap;
import org.onosproject.store.service.StorageService;
import org.onosproject.store.service.Versioned;
import org.opencord.maclearner.api.DefaultMacLearner;
import org.opencord.maclearner.api.MacDeleteResult;
import org.opencord.maclearner.api.MacLearnerEvent;
import org.opencord.maclearner.api.MacLearnerKey;
import org.opencord.maclearner.api.MacLearnerListener;
import org.opencord.maclearner.api.MacLearnerProvider;
import org.opencord.maclearner.api.MacLearnerProviderService;
import org.opencord.maclearner.api.MacLearnerService;
import org.opencord.maclearner.api.MacLearnerValue;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.Date;
import java.util.Dictionary;
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
import static org.onlab.packet.DHCP.DHCPOptionCode.OptionCode_MessageType;
import static org.onlab.util.Tools.groupedThreads;
import static org.opencord.maclearner.app.impl.OsgiPropertyConstants.CACHE_DURATION_DEFAULT;
import static org.opencord.maclearner.app.impl.OsgiPropertyConstants.CACHE_DURATION;
import static org.opencord.maclearner.app.impl.OsgiPropertyConstants.ENABLE_DEVICE_LISTENER;
import static org.opencord.maclearner.app.impl.OsgiPropertyConstants.ENABLE_DEVICE_LISTENER_DEFAULT;
import static org.osgi.service.component.annotations.ReferenceCardinality.MANDATORY;

/**
 * Mac Learner Service implementation.
 */
@Component(immediate = true,
        property = {
                CACHE_DURATION + ":Integer=" + CACHE_DURATION_DEFAULT,
                ENABLE_DEVICE_LISTENER + ":Boolean=" + ENABLE_DEVICE_LISTENER_DEFAULT
        },
        service = MacLearnerService.class
)
public class MacLearnerManager
        extends AbstractListenerProviderRegistry<MacLearnerEvent, MacLearnerListener,
        MacLearnerProvider, MacLearnerProviderService>
        implements MacLearnerService {

    private static final String MAC_LEARNER_APP = "org.opencord.maclearner";
    private static final String MAC_LEARNER = "maclearner";
    private ApplicationId appId;

    private final ScheduledExecutorService scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
    private ScheduledFuture scheduledFuture;

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = MANDATORY)
    protected MastershipService mastershipService;

    @Reference(cardinality = MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = MANDATORY)
    protected StorageService storageService;


    @Reference(cardinality = MANDATORY)
    protected ComponentConfigService componentConfigService;

    private MacLearnerPacketProcessor macLearnerPacketProcessor =
            new MacLearnerPacketProcessor();

    private DeviceListener deviceListener = new InternalDeviceListener();

    /**
     * Minimum duration of mapping, mapping can be exist until 2*cacheDuration because of cleanerTimer fixed rate.
     */
    protected int cacheDurationSec = CACHE_DURATION_DEFAULT;

    /**
     * Register a device event listener for removing mappings from MAC Address Map for removed events.
     */
    protected boolean enableDeviceListener = ENABLE_DEVICE_LISTENER_DEFAULT;

    private ConsistentMap<DeviceId, Set<PortNumber>> ignoredPortsMap;
    private ConsistentMap<MacLearnerKey, MacLearnerValue> macAddressMap;

    protected ExecutorService eventExecutor;

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
        //mac learner must process the packet before director processors
        packetService.addProcessor(macLearnerPacketProcessor,
                PacketProcessor.advisor(2));
        if (enableDeviceListener) {
            deviceService.addListener(deviceListener);
        }
        createSchedulerForClearMacMappings();
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
            if (!mastershipService.isLocalMaster(entry.getKey().getDeviceId())) {
                return;
            }
            if (curDate.getTime() - entry.getValue().value().getTimestamp() > cacheDurationSec * 1000) {
                removeFromMacAddressMap(entry.getKey());
            }
        }
    }

    @Deactivate
    public void deactivate() {
        if (scheduledFuture != null) {
            scheduledFuture.cancel(true);
        }
        packetService.removeProcessor(macLearnerPacketProcessor);
        if (enableDeviceListener) {
            deviceService.removeListener(deviceListener);
        }
        eventDispatcher.removeSink(MacLearnerEvent.class);
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

        Boolean enableDevListener = Tools.isPropertyEnabled(properties, ENABLE_DEVICE_LISTENER);
        if (enableDevListener != null && enableDeviceListener != enableDevListener) {
            enableDeviceListener = enableDevListener;
            log.info("enableDeviceListener parameter changed to: {}", enableDeviceListener);
            if (this.enableDeviceListener) {
                deviceService.addListener(deviceListener);
            } else {
                deviceService.removeListener(deviceListener);
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
        return removeFromMacAddressMap(key);
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
        entriesToDelete.forEach(e -> removeFromMacAddressMap(e.getKey()));
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
        entriesToDelete.forEach(e -> removeFromMacAddressMap(e.getKey()));
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

    private class MacLearnerPacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            // process the packet and get the payload
            Ethernet packet = context.inPacket().parsed();

            if (packet == null) {
                log.warn("Packet is null");
                return;
            }

            PortNumber sourcePort = context.inPacket().receivedFrom().port();
            DeviceId deviceId = context.inPacket().receivedFrom().deviceId();

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
                        DHCP dhcpPayload = (DHCP) udpPacket.getPayload();
                        //This packet is dhcp.
                        VlanId vlanId = packet.getQinQVID() != -1 ?
                                VlanId.vlanId(packet.getQinQVID()) : VlanId.vlanId(packet.getVlanID());
                        processDhcpPacket(context, packet, dhcpPayload, sourcePort, deviceId, vlanId);
                    }
                }
            }
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
            } else if (prevMacAddress == null || !prevMacAddress.value().getMacAddress().equals(macAddress)) {
                // Not sending event for already mapped
                log.info("Mapped MAC: {} for port: {} of deviceId: {} and vlanId: {}",
                        macAddress, portNumber, deviceId, vlanId);
                sendMacLearnerEvent(MacLearnerEvent.Type.ADDED, deviceId, portNumber, vlanId, macAddress);
            }
        }

    }

    private MacDeleteResult removeFromMacAddressMap(MacLearnerKey macLearnerKey) {
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
                switch (event.type()) {
                    case DEVICE_REMOVED:
                        deleteMacMappings(event.subject().id());
                        break;
                    case PORT_REMOVED:
                        deleteMacMappings(event.subject().id(), event.port().number());
                        break;
                    default:
                        log.debug("Unhandled device event for Mac Learner: {}", event.type());
                }
            });
        }

        @Override
        public boolean isRelevant(DeviceEvent event) {
            return mastershipService.isLocalMaster(event.subject().id());
        }

    }

}
