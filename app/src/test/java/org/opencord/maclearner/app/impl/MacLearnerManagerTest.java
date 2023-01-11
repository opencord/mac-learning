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
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.packet.OutboundPacket;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.onlab.junit.TestTools.assertAfter;

/**
 * Set of tests of the Mac Learner ONOS application component.
 */
public class MacLearnerManagerTest extends TestBaseMacLearner {

    private static final int DELAY = 250;
    private static final int PROCESSING_LENGTH = 500;

    @Before
    public void setUp() throws IOException {
        setUpApp();
    }

    @After
    public void tearDown() {
        this.macLearnerManager.deactivate();
    }

    private static final MacAddress CLIENT_MAC = MacAddress.valueOf("00:00:00:00:00:01");
    public static final VlanId CLIENT_VLAN = VlanId.vlanId("100");
    private static final VlanId CLIENT_QINQ_VLAN = VlanId.vlanId("200");
    public static final DeviceId OLT_DEVICE_ID = DeviceId.deviceId("of:0000b86a974385f7");
    public static final PortNumber UNI_PORT = PortNumber.portNumber(16);
    public static final ConnectPoint CLIENT_CP = new ConnectPoint(OLT_DEVICE_ID, UNI_PORT);
    public static final DeviceId AGG_DEVICE_ID = DeviceId.deviceId("of:0000000000000001");
    public static final PortNumber AGG_OLT_PORT = PortNumber.portNumber(10);
    public static final PortNumber OLT_NNI_PORT = PortNumber.portNumber(1048576);
    public static final ConnectPoint NNI_CP = new ConnectPoint(OLT_DEVICE_ID, OLT_NNI_PORT);
    public static final String OLT_SERIAL_NUMBER = "BBSIM_OLT_1";
    private static final MacAddress SERVER_MAC = MacAddress.valueOf("00:00:00:00:00:11");

    @Test
    public void testSingleTagDhcpPacket() {
        packetService.processPacket(new TestDhcpRequestPacketContext(CLIENT_MAC,
                CLIENT_VLAN,
                VlanId.NONE,
                CLIENT_CP));
        assertAfter(DELAY, PROCESSING_LENGTH, () -> {
            Optional<MacAddress> macAddress =
                    macLearnerManager.getMacMapping(CLIENT_CP.deviceId(),
                                                    CLIENT_CP.port(), CLIENT_VLAN);
            assertTrue(macAddress.isPresent());
            assertEquals(CLIENT_MAC, macAddress.get());
        });
    }

    @Test
    public void testDoubleTagDhcpPacket() {
        packetService.processPacket(new TestDhcpRequestPacketContext(CLIENT_MAC,
                CLIENT_VLAN,
                CLIENT_QINQ_VLAN,
                CLIENT_CP));
        assertAfter(DELAY, PROCESSING_LENGTH, () -> {
            Optional<MacAddress> macAddress = macLearnerManager.getMacMapping(CLIENT_CP.deviceId(),
                                                                              CLIENT_CP.port(), CLIENT_QINQ_VLAN);
            assertTrue(macAddress.isPresent());
            assertEquals(CLIENT_MAC, macAddress.get());
        });

    }

    @Test
    public void testHostProviding() {
        packetService.processPacket(new TestDhcpRequestPacketContext(CLIENT_MAC,
                CLIENT_VLAN,
                CLIENT_QINQ_VLAN,
                CLIENT_CP));
        assertAfter(DELAY, PROCESSING_LENGTH, () -> {
            HostId hostId = HostId.hostId(CLIENT_MAC, CLIENT_QINQ_VLAN);
            Host host = hostService.getHost(hostId);
            assertNotNull(host);
            assertEquals(OLT_DEVICE_ID, host.location().deviceId());
            assertEquals(UNI_PORT, host.location().port());
            Optional<HostLocation> optAuxLoc = host.auxLocations().stream().findFirst();
            assertTrue(optAuxLoc.isPresent());
            assertEquals(AGG_DEVICE_ID, optAuxLoc.get().deviceId());
            assertEquals(AGG_OLT_PORT, optAuxLoc.get().port());
        });
    }

    @Test
    public void testDhcpForwardClientRequest() {
        this.macLearnerManager.enableDhcpForward = true;
        TestDhcpRequestPacketContext dhcpRequest = new TestDhcpRequestPacketContext(CLIENT_MAC, CLIENT_VLAN,
                VlanId.NONE, CLIENT_CP);
        ByteBuffer inBuffer = dhcpRequest.inPacket().unparsed();

        packetService.processPacket(dhcpRequest);

        assertAfter(DELAY, PROCESSING_LENGTH, () -> {
            OutboundPacket emittedPacket = packetService.emittedPacket;
            ByteBuffer outBuffer = emittedPacket.data();
            DeviceId deviceId = emittedPacket.sendThrough();
            TrafficTreatment treatment = emittedPacket.treatment();
            List<Instruction> instructions = treatment.allInstructions();

            assertEquals(deviceId, OLT_DEVICE_ID);
            for (Instruction instruction : instructions) {
                if (instruction instanceof Instructions.OutputInstruction) {
                    assertEquals(OLT_NNI_PORT, ((Instructions.OutputInstruction) instruction).port());
                }
            }

            // Test for packet not modified
            assertEquals(0, inBuffer.compareTo(outBuffer));
       });
    }

    @Test
    public void testDhcpForwardServerResponse() {
        this.macLearnerManager.enableDhcpForward = true;
        testDhcpForwardClientRequest();

        TestDhcpResponsePacketContext dhcpResponse = new TestDhcpResponsePacketContext(CLIENT_MAC, SERVER_MAC,
                CLIENT_VLAN, VlanId.NONE, NNI_CP);
        ByteBuffer inBuffer = dhcpResponse.inPacket().unparsed();

        packetService.processPacket(dhcpResponse);

        assertAfter(DELAY, PROCESSING_LENGTH, () -> {
            OutboundPacket emittedPacket = packetService.emittedPacket;
            ByteBuffer outBuffer = emittedPacket.data();

            DeviceId deviceId = emittedPacket.sendThrough();
            TrafficTreatment treatment = emittedPacket.treatment();
            List<Instruction> instructions = treatment.allInstructions();

            assertEquals(deviceId, OLT_DEVICE_ID);
            for (Instruction instruction : instructions) {
                if (instruction instanceof Instructions.OutputInstruction) {
                    assertEquals(UNI_PORT, ((Instructions.OutputInstruction) instruction).port());
                }
            }

            // Test for packet not modified
            assertEquals(0, inBuffer.compareTo(outBuffer));
        });
    }
}
