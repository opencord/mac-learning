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
package org.opencord.maclearner.api;

import org.apache.commons.lang.builder.ToStringBuilder;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;

/**
 * Default Mac Learner object model implementation.
 */
public class DefaultMacLearner implements MacLearner {

    private MacLearnerKey macLearnerKey;
    private MacAddress macAddress;

    public static final String DEVICE_ID_FN = "deviceId";
    public static final String PORT_NUMBER_FN = "portNumber";
    public static final String VLAN_ID_FN = "vlanId";
    public static final String MAC_ADDRESS_FN = "macAddress";

    @Override
    public DeviceId deviceId() {
        return macLearnerKey.getDeviceId();
    }

    @Override
    public PortNumber portNumber() {
        return macLearnerKey.getPortNumber();
    }

    @Override
    public VlanId vlanId() {
        return macLearnerKey.getVlanId();
    }

    @Override
    public MacAddress macAddress() {
        return macAddress;
    }

    public DefaultMacLearner(DeviceId deviceId, PortNumber portNumber, VlanId vlanId, MacAddress macAddress) {
        this.macLearnerKey = new MacLearnerKey(deviceId, portNumber, vlanId);
        this.macAddress = macAddress;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append(DEVICE_ID_FN, deviceId())
                .append(PORT_NUMBER_FN, portNumber())
                .append(VLAN_ID_FN, vlanId())
                .append(MAC_ADDRESS_FN, macAddress())
                .toString();
    }

}
