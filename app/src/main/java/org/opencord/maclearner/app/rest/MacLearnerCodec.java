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
package org.opencord.maclearner.app.rest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.codec.CodecContext;
import org.onosproject.codec.JsonCodec;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.opencord.maclearner.api.DefaultMacLearner;
import org.opencord.maclearner.api.MacLearner;
import org.opencord.maclearner.api.MacLearnerKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * MAC Learner JSON codec.
 */
public final class MacLearnerCodec extends JsonCodec<MacLearner> {

    private static final Logger log = LoggerFactory.getLogger(MacLearnerCodec.class);

    @Override
    public ObjectNode encode(MacLearner macLearner, CodecContext context) {
        checkNotNull(macLearner, "macLearner cannot be null");

        ObjectMapper mapper = context.mapper();
        ObjectNode ofAgentNode = mapper.createObjectNode();
        ofAgentNode
                .put(DefaultMacLearner.DEVICE_ID_FN, macLearner.deviceId().toString())
                .put(DefaultMacLearner.PORT_NUMBER_FN, macLearner.portNumber().toString())
                .put(DefaultMacLearner.VLAN_ID_FN, macLearner.vlanId().toString())
                .put(DefaultMacLearner.MAC_ADDRESS_FN, macLearner.macAddress().toString());
        return ofAgentNode;
    }

    public ObjectNode encodePort(MacLearnerKey ignoredPort, CodecContext context) {
        checkNotNull(ignoredPort, "ignoredPort cannot be null");

        ObjectMapper mapper = context.mapper();
        ObjectNode ofAgentNode = mapper.createObjectNode();
        ofAgentNode
                .put(DefaultMacLearner.DEVICE_ID_FN, ignoredPort.getDeviceId().toString())
                .put(DefaultMacLearner.PORT_NUMBER_FN, ignoredPort.getPortNumber().toString());
        return ofAgentNode;
    }

    public ObjectNode encodeMac(MacAddress macAddress, CodecContext context) {
        checkNotNull(macAddress, "macAddress cannot be null");

        ObjectMapper mapper = context.mapper();
        ObjectNode ofAgentNode = mapper.createObjectNode();
        ofAgentNode
                .put(DefaultMacLearner.MAC_ADDRESS_FN, macAddress.toString());
        return ofAgentNode;
    }

    @Override
    public MacLearner decode(ObjectNode json, CodecContext context) {
        JsonNode deviceId = json.get(DefaultMacLearner.DEVICE_ID_FN);
        checkNotNull(deviceId);
        JsonNode portNumber = json.get(DefaultMacLearner.PORT_NUMBER_FN);
        checkNotNull(portNumber);
        JsonNode vlanId = json.get(DefaultMacLearner.VLAN_ID_FN);
        checkNotNull(vlanId);
        JsonNode macAddress = json.get(DefaultMacLearner.MAC_ADDRESS_FN);
        checkNotNull(macAddress);

        return new DefaultMacLearner(DeviceId.deviceId(deviceId.asText()),
                PortNumber.portNumber(portNumber.asLong()),
                VlanId.vlanId(vlanId.shortValue()),
                MacAddress.valueOf(macAddress.asText()));
    }

}
