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
import org.opencord.maclearner.api.MacDeleteResult;
import org.opencord.maclearner.api.MacLearnerService;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;

/**
 * Deletes MAC Address information of client connected to requested device and port.
 */
@Service
@Command(scope = "onos", name = "mac-learner-delete-mapping",
        description = "Deletes MAC Address information of client connected to requested device and port")
public class MacLearnerDeleteMapping extends AbstractShellCommand {

    @Argument(index = 0, name = "deviceId",
            description = "OpenFlow Device Id",
            required = true)
    @Completion(MappedDeviceIdCompleter.class)
    String devId = null;

    @Argument(index = 1, name = "portNo",
            description = "Integer value of Port Number",
            required = true)
    @Completion(MappedPortNumberCompleter.class)
    Integer portNo;

    @Argument(index = 2, name = "vlanId",
            description = "Short value of Vlan Id",
            required = true)
    Short vlanId;

    private static final String DELETE_MAPPING_SUCCESS = "Mac Mapping Successfully Deleted.";
    private static final String DELETE_MAPPING_FAILURE = "Mac Mapping Deletion Failed.";
    private static final String MAPPING_NOT_FOUND = "Mac Mapping requested to delete is not found.";

    @Override
    protected void doExecute() {
        MacLearnerService macLearnerService = AbstractShellCommand.get(MacLearnerService.class);
        try {
            if (portNo == null || devId == null || vlanId == null) {
                throw new IllegalArgumentException();
            }

            MacDeleteResult result = macLearnerService.deleteMacMapping(DeviceId.deviceId(devId),
                    PortNumber.portNumber(portNo),
                    VlanId.vlanId(vlanId));
            switch (result) {
                case SUCCESSFUL:
                    print(DELETE_MAPPING_SUCCESS);
                    break;
                case NOT_EXIST:
                    print(MAPPING_NOT_FOUND);
                    break;
                case UNSUCCESSFUL:
                    print(DELETE_MAPPING_FAILURE);
                    break;
                default:
                    throw new IllegalArgumentException();
            }

        } catch (IllegalArgumentException e) {
            String msg = String.format("Exception occurred while executing %s command",
                    this.getClass().getSimpleName());
            print(msg);
            log.error(msg, e);
        }
    }

}
