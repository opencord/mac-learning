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
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;

/**
 * Representation of a mac learner object.
 */
public interface MacLearner {

    /**
     * Returns the device identifier.
     *
     * @return device id
     */
    DeviceId deviceId();

    /**
     * Returns from which port the mac address is learned.
     * @return port number
     */
    PortNumber portNumber();

    /**
     * Returns which vlan id of the package the mac address is learned from.
     * If packet is double tagged, vlan id is equal to QinQVID.
     * @return vlan id
     */
    VlanId vlanId();

    /**
     * Returns Mac Address information.
     * @return mac address
     */
    MacAddress macAddress();

}
