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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.HostLocation;
import org.onosproject.net.PortNumber;

import java.io.IOException;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Set of tests of the Mac Learner ONOS application component.
 */
public class MacLearnerManagerTest extends TestBaseMacLearner {

    @Before
    public void setUp() throws IOException {
        setUpApp();
    }

    @After
    public void tearDown() {
        this.macLearnerManager.deactivate();
    }

    private static final MacAddress CLIENT_MAC = MacAddress.valueOf("00:00:00:00:00:01");
    private static final VlanId CLIENT_VLAN = VlanId.vlanId("100");
    private static final VlanId CLIENT_QINQ_VLAN = VlanId.vlanId("200");
    public static final DeviceId OLT_DEVICE_ID = DeviceId.deviceId("of:0000b86a974385f7");
    public static final PortNumber UNI_PORT = PortNumber.portNumber(16);
    public static final ConnectPoint CLIENT_CP = new ConnectPoint(OLT_DEVICE_ID, UNI_PORT);
    public static final DeviceId AGG_DEVICE_ID = DeviceId.deviceId("of:0000000000000001");
    public static final PortNumber AGG_OLT_PORT = PortNumber.portNumber(10);
    public static final PortNumber OLT_NNI_PORT = PortNumber.portNumber(1048576);

    @Test
    public void testSingleTagDhcpPacket() {
        packetService.processPacket(new TestDhcpRequestPacketContext(CLIENT_MAC,
                CLIENT_VLAN,
                VlanId.NONE,
                CLIENT_CP));
        Optional<MacAddress> macAddress = macLearnerManager.getMacMapping(CLIENT_CP.deviceId(),
                CLIENT_CP.port(), CLIENT_VLAN);
        assertTrue(macAddress.isPresent());
        assertEquals(CLIENT_MAC, macAddress.get());
    }

    @Test
    public void testDoubleTagDhcpPacket() {
        packetService.processPacket(new TestDhcpRequestPacketContext(CLIENT_MAC,
                CLIENT_VLAN,
                CLIENT_QINQ_VLAN,
                CLIENT_CP));
        Optional<MacAddress> macAddress = macLearnerManager.getMacMapping(CLIENT_CP.deviceId(),
                CLIENT_CP.port(), CLIENT_QINQ_VLAN);
        assertTrue(macAddress.isPresent());
        assertEquals(CLIENT_MAC, macAddress.get());
    }

    @Test
    public void testHostProviding() {
        packetService.processPacket(new TestDhcpRequestPacketContext(CLIENT_MAC,
                CLIENT_VLAN,
                CLIENT_QINQ_VLAN,
                CLIENT_CP));
        HostId hostId = HostId.hostId(CLIENT_MAC, CLIENT_QINQ_VLAN);
        Host host = hostService.getHost(hostId);
        assertNotNull(host);
        assertEquals(OLT_DEVICE_ID, host.location().deviceId());
        assertEquals(UNI_PORT, host.location().port());
        Optional<HostLocation> optAuxLoc = host.auxLocations().stream().findFirst();
        assertTrue(optAuxLoc.isPresent());
        assertEquals(AGG_DEVICE_ID, optAuxLoc.get().deviceId());
        assertEquals(AGG_OLT_PORT, optAuxLoc.get().port());
    }

}
