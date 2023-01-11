/*
 * Copyright 2020-2023 Open Networking Foundation (ONF) and the ONF Contributors
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

import org.onlab.packet.EthType;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.net.HostId;
import org.onosproject.net.HostLocation;

/**
 * Mac Learner Host Location Service.
 */
public interface MacLearnerHostLocationService {

    /**
     * Create or update host information.
     * Will not update IP if IP is null, all zero or self-assigned.
     *
     * @param hid                  host ID
     * @param srcMac               source Mac address
     * @param dstMac               destination Mac address
     * @param vlan                 VLAN ID
     * @param innerVlan            inner VLAN ID
     * @param outerTpid            outer TPID
     * @param hloc                 host location
     * @param auxLoc               auxiliary location
     * @param ip                   source IP address or null if not updating
     */
    void createOrUpdateHost(HostId hid, MacAddress srcMac, MacAddress dstMac, VlanId vlan, VlanId innerVlan,
                            EthType outerTpid, HostLocation hloc, HostLocation auxLoc, IpAddress ip);

    /**
     * Updates IP address for an existing host.
     *
     * @param hid host ID
     * @param ip  IP address
     */
    void updateHostIp(HostId hid, IpAddress ip);

    /**
     * Removes host completely.
     *
     * @param macAddress           source Mac address
     * @param vlanId               VLAN ID
     */
    void vanishHost(MacAddress macAddress, VlanId vlanId);

}
