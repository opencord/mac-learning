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
package org.opencord.maclearner.app.cli;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onlab.packet.VlanId;
import org.opencord.maclearner.api.MacLearnerKey;
import org.opencord.maclearner.api.MacLearnerService;
import org.onlab.packet.MacAddress;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;

import java.util.Map;
import java.util.Optional;

/**
 * Gets MAC Address information of client connected to requested device and port.
 */
@Service
@Command(scope = "onos", name = "mac-learner-get-mapping",
        description = "Gets MAC Address information of client connected to requested device and port")
public class MacLearnerGetMapping extends AbstractShellCommand {

    @Argument(index = 0, name = "deviceId",
            description = "OpenFlow Device Id")
    @Completion(MappedDeviceIdCompleter.class)
    String devId = null;

    @Argument(index = 1, name = "portNo",
            description = "Integer value of Port Number")
    @Completion(MappedPortNumberCompleter.class)
    Integer portNo;

    @Argument(index = 2, name = "vlanId",
            description = "Short value of Vlan Id")
    Short vlanId;

    @Override
    protected void doExecute() {
        try {
            MacLearnerService macLearnerService = AbstractShellCommand.get(MacLearnerService.class);
            if (portNo == null && devId == null && vlanId == null) {
                Map<MacLearnerKey, MacAddress> mapMacAddressMap = macLearnerService.getAllMappings();
                for (Map.Entry<MacLearnerKey, MacAddress> entry : mapMacAddressMap.entrySet()) {
                    print("Client with MAC: %s and VlanID: %s, uses port number: %s of device with id: %s",
                          entry.getValue(),
                          entry.getKey().getVlanId(),
                          entry.getKey().getPortNumber(),
                          entry.getKey().getDeviceId());
                }
            } else if (portNo != null && devId != null && vlanId != null) {
                Optional<MacAddress> macAddress = macLearnerService.getMacMapping(DeviceId.deviceId(devId),
                                                                                  PortNumber.portNumber(portNo),
                                                                                  VlanId.vlanId(vlanId));
                if (macAddress.isEmpty()) {
                    print("MAC Address not found with given parameters.\nUse -1 for VlanId=None");
                } else {
                    print(String.format("MAC: %s", macAddress.get()));
                }
            } else {
                print("Either device id, port number and vlan id must be entered or not at all!");
            }

        } catch (IllegalArgumentException e) {
            String msg = String.format("Exception occurred while executing %s command",
                    this.getClass().getSimpleName());
            print(msg);
            log.error(msg, e);
        }
    }

}
