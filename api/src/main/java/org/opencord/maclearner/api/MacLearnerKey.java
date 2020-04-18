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

import org.onlab.packet.VlanId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;

import java.util.Objects;

/**
 * Key of Mac Address Map.
 */
public class MacLearnerKey {

    private DeviceId deviceId;
    private PortNumber portNumber;
    private VlanId vlanId;

    public DeviceId getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(DeviceId deviceId) {
        this.deviceId = deviceId;
    }

    public PortNumber getPortNumber() {
        return portNumber;
    }

    public void setPortNumber(PortNumber portNumber) {
        this.portNumber = portNumber;
    }

    public VlanId getVlanId() {
        return vlanId;
    }

    public void setVlanId(VlanId vlanId) {
        this.vlanId = vlanId;
    }

    public MacLearnerKey(DeviceId deviceId, PortNumber portNumber, VlanId vlanId) {
        this.deviceId = deviceId;
        this.portNumber = portNumber;
        this.vlanId = vlanId;
    }

    @Override
    public String toString() {
        return "MacLearnerKey{" +
                "deviceId=" + deviceId +
                ", portNumber=" + portNumber +
                ", vlanId=" + vlanId +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        MacLearnerKey that = (MacLearnerKey) o;
        return Objects.equals(deviceId, that.deviceId) &&
                Objects.equals(portNumber, that.portNumber) &&
                Objects.equals(vlanId, that.vlanId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(deviceId, portNumber, vlanId);
    }

}
