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
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.opencord.maclearner.api.MacLearnerService;

import java.util.Map;
import java.util.Set;

/**
 * Gets ignored port information for MAC Mapping.
 */
@Service
@Command(scope = "onos", name = "mac-learner-list-ignored-ports",
        description = "Gets ignored port information for MAC Mapping")
public class MacLearnerListIgnoredPorts extends AbstractShellCommand {

    @Argument(index = 0, name = "deviceId",
            description = "Device Id")
    @Completion(MappedDeviceIdCompleter.class)
    String devId = null;

    @Override
    protected void doExecute() {
        try {
            MacLearnerService macLearnerService = AbstractShellCommand.get(MacLearnerService.class);
            Map<DeviceId, Set<PortNumber>> ignoredPorts = macLearnerService.getIgnoredPorts();
            if (devId == null) {
                if (ignoredPorts != null && !ignoredPorts.isEmpty()) {
                    for (Map.Entry<DeviceId, Set<PortNumber>> entry : ignoredPorts.entrySet()) {
                        print("Port(s): %s ignored of device with ID: %s", entry.getValue(), entry.getKey());
                    }
                } else {
                    print("There is no ignored port.");
                }
            } else {
                Set<PortNumber> portNumbers = ignoredPorts.get(DeviceId.deviceId(devId));
                if (!ignoredPorts.isEmpty()) {
                    print("Port(s): %s ignored of device with ID: %s", portNumbers, devId);
                } else {
                    print("There is no ignored port of device with ID: %s", devId);
                }
            }

        } catch (IllegalArgumentException e) {
            String msg = String.format("Exception occurred while executing %s command",
                    this.getClass().getSimpleName());
            print(msg);
            log.error(msg, e);
        }
    }

}
