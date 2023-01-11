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
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.opencord.maclearner.api.MacLearnerService;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;

/**
 * Removes a port of device from Ignore Map.
 */
@Service
@Command(scope = "onos", name = "mac-learner-remove-ignore-port",
        description = "Removes a port of device from Ignore Map")
public class MacLearnerRemoveIgnorePort extends AbstractShellCommand {

    @Argument(index = 0, name = "deviceId",
            description = "OpenFlow Device Id",
            required = true)
    String devId = null;

    @Argument(index = 1, name = "portNo",
            description = "Integer value of Port Number",
            required = true)
    Integer portNo;

    @Override
    protected void doExecute() {
        try {
            MacLearnerService macLearnerService = AbstractShellCommand.get(MacLearnerService.class);
            macLearnerService.removeFromIgnoredPorts(DeviceId.deviceId(devId),
                                                     PortNumber.portNumber(portNo));

        } catch (IllegalArgumentException e) {
            String msg = String.format("Exception occurred while executing %s command",
                    this.getClass().getSimpleName());
            print(msg);
            log.error(msg, e);
        }
    }

}
