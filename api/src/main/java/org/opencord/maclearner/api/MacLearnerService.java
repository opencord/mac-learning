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
package org.opencord.maclearner.api;

import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.event.ListenerService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Mac Learner Service.
 */
public interface MacLearnerService extends ListenerService<MacLearnerEvent, MacLearnerListener> {

    /**
     * Adding a port to ignore map to prevent mac mapping.
     * @param deviceId openflow device id
     * @param portNumber port number
     */
    void addPortToIgnore(DeviceId deviceId, PortNumber portNumber);

    /**
     * Removing a port from ignore port map.
     * @param deviceId openflow device id
     * @param portNumber port number
     */
    void removeFromIgnoredPorts(DeviceId deviceId, PortNumber portNumber);

    /**
     * Getting All MAC Mappings.
     * @return Map of MAC Addresses by device id, port number and vlan id
     */
    Map<MacLearnerKey, MacAddress> getAllMappings();

    /**
     * Getting Requested MAC Address.
     * @param deviceId openflow device id
     * @param portNumber port number
     * @param vlanId vlan id
     * @return  MAC Address of requested device id, port number and vlan id
     */
    Optional<MacAddress> getMacMapping(DeviceId deviceId, PortNumber portNumber, VlanId vlanId);

    /**
     * Deleting a MAC Mapping.
     * @param deviceId openflow device id
     * @param portNumber port number
     * @param vlanId vlan id
     * @return MacDeleteResult situation after method call
     */
    MacDeleteResult deleteMacMapping(DeviceId deviceId, PortNumber portNumber, VlanId vlanId);

    /**
     * Deleting MAC Mappings of port.
     * @param deviceId openflow device id
     * @param portNumber port number
     * @return true if the mappings deleted successfully; false otherwise
     */
    boolean deleteMacMappings(DeviceId deviceId, PortNumber portNumber);

    /**
     * Deleting MAC Mappings of device.
     * @param deviceId openflow device id
     * @return true if the mappings deleted successfully; false otherwise
     */
    boolean deleteMacMappings(DeviceId deviceId);

    /**
     * Getting Device List in MAC Mapping List.
     * @return mapped ONOS devices
     */
    Set<DeviceId> getMappedDevices();

    /**
     * Getting Port Number List in MAC Mapping List.
     * @return mapped port numbers
     */
    Set<PortNumber> getMappedPorts();

    /**
     * Getting Ignored Ports for MAC Mapping.
     * @return device and its ignored ports map
     */
    Map<DeviceId, Set<PortNumber>> getIgnoredPorts();

}
