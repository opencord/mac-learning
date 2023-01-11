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
package org.opencord.maclearner.app.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.rest.AbstractWebResource;
import org.opencord.maclearner.api.DefaultMacLearner;
import org.opencord.maclearner.api.MacDeleteResult;
import org.opencord.maclearner.api.MacLearnerKey;
import org.opencord.maclearner.api.MacLearnerService;
import org.slf4j.Logger;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static javax.ws.rs.core.Response.Status.NO_CONTENT;
import static javax.ws.rs.core.Response.Status.OK;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Mac Learner web resource.
 */
@Path("maclearner")
public class MacLearnerWebResource extends AbstractWebResource {

    MacLearnerCodec codec = new MacLearnerCodec();

    private final MacLearnerService macLearnerService = get(MacLearnerService.class);

    private final Logger log = getLogger(getClass());

    private static final String INVALID_PATH_PARAMETERS = "Invalid path parameters";
    private static final String PATH_DELIMITER = "/";

    /**
     * Get all MAC Mappings.
     *
     * @return list of MAC Mapping json object with deviceId, portNumber, vlanId, macAddress fields
     */
    @GET
    @Path("/mapping/all")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAllMappings() {
        Map<MacLearnerKey, MacAddress> macMappings = macLearnerService.getAllMappings();
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = mapper.createObjectNode();
        ArrayNode macArray = mapper.createArrayNode();
        if (macMappings == null) {
            root.set("data", macArray);
            return Response.ok(root, MediaType.APPLICATION_JSON_TYPE).build();
        } else {
            macMappings.forEach((k, v) -> macArray.add(
                    codec.encode(new DefaultMacLearner(k.getDeviceId(),
                            k.getPortNumber(),
                            k.getVlanId(),
                            v), this)
            ));
        }
        root.set("data", macArray);
        return Response.ok(root, MediaType.APPLICATION_JSON_TYPE).build();
    }

    /**
     * Get MAC Mapping for request paramaters.
     *
     * @param ofDeviceId device id
     * @param portNumber port number
     * @param vlanId     vlan id
     * @return MAC Address json object with macAddress field
     * 204 NO_CONTENT if it does not exist
     */
    @GET
    @Path("/mapping/{ofDeviceId}/{portNumber}/{vlanId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getMacMapping(@PathParam("ofDeviceId") String ofDeviceId,
                                  @PathParam("portNumber") Integer portNumber,
                                  @PathParam("vlanId") Short vlanId) {
        Optional<MacAddress> mac = macLearnerService.getMacMapping(DeviceId.deviceId(ofDeviceId),
                PortNumber.portNumber(portNumber),
                VlanId.vlanId(vlanId));
        if (mac.isEmpty()) {
            log.warn("MAC Address not found for: ofDeviceId:{} portNumber:{} vlanId:{}",
                    ofDeviceId, portNumber, vlanId);
            return Response.status(NO_CONTENT).build();
        }
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = mapper.createObjectNode();
        root.set("data", codec.encodeMac(mac.get(), this));
        return Response.ok(root, MediaType.APPLICATION_JSON_TYPE).status(OK).build();
    }

    /**
     * Delete MAC Mapping for request paramaters.
     *
     * @param ofDeviceId device id
     * @param portNumber port number
     * @param vlanId     vlan id
     * @return URI of request
     */
    @DELETE
    @Path("/mapping/{ofDeviceId}/{portNumber}/{vlanId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response deleteMacMapping(@PathParam("ofDeviceId") String ofDeviceId,
                                     @PathParam("portNumber") Integer portNumber,
                                     @PathParam("vlanId") Short vlanId) {
        try {
            if (ofDeviceId == null || portNumber == null || vlanId == null) {
                throw new IllegalArgumentException(INVALID_PATH_PARAMETERS);
            }
            MacDeleteResult deleteResult = macLearnerService.deleteMacMapping(DeviceId.deviceId(ofDeviceId),
                    PortNumber.portNumber(portNumber),
                    VlanId.vlanId(vlanId));
            if (deleteResult.equals(MacDeleteResult.UNSUCCESSFUL)) {
                return Response.status(NO_CONTENT).build();
            }
            return Response
                    .created(new URI("/delete/mapping/" +
                            ofDeviceId + PATH_DELIMITER +
                            portNumber + PATH_DELIMITER +
                            vlanId))
                    .status(OK)
                    .build();
        } catch (URISyntaxException e) {
            log.error("URI Syntax Exception occurred while deleting MAC Mapping " +
                            "for deviceId: {} portNumber: {} vlanId: {}",
                    ofDeviceId, portNumber, vlanId, e);
            return Response.serverError().build();
        }
    }

    /**
     * Delete MAC Mappings for specific port of a device.
     *
     * @param ofDeviceId device id
     * @param portNumber port number
     * @return URI of request
     */
    @DELETE
    @Path("/mappings/{ofDeviceId}/{portNumber}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response deleteMacMappings(@PathParam("ofDeviceId") String ofDeviceId,
                                      @PathParam("portNumber") Integer portNumber) {
        try {
            if (ofDeviceId == null || portNumber == null) {
                throw new IllegalArgumentException(INVALID_PATH_PARAMETERS);
            }
            boolean deleteSuccess = macLearnerService.deleteMacMappings(DeviceId.deviceId(ofDeviceId),
                    PortNumber.portNumber(portNumber));
            if (!deleteSuccess) {
                return Response.status(NO_CONTENT).build();
            }
            return Response.created(new URI("/delete/mappings/" +
                    ofDeviceId + PATH_DELIMITER +
                    portNumber)).status(OK).build();
        } catch (URISyntaxException e) {
            log.error("URI Syntax Exception occurred while deleting MAC Mappings for deviceId: {} portNumber: {}",
                    ofDeviceId, portNumber, e);
            return Response.serverError().build();
        }
    }

    /**
     * Get ignored ports for MAC Mapping.
     *
     * @return list of ignored port json object with deviceId and portNumber fields
     */
    @GET
    @Path("/ports/ignored")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getIgnoredPorts() {
        Map<DeviceId, Set<PortNumber>> ignoredPorts = macLearnerService.getIgnoredPorts();
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = mapper.createObjectNode();
        ArrayNode ignoredPortsArray = mapper.createArrayNode();
        if (ignoredPorts == null) {
            root.set("data", ignoredPortsArray);
            return Response.ok(root, MediaType.APPLICATION_JSON_TYPE).build();
        } else {
            for (Map.Entry<DeviceId, Set<PortNumber>> entry : ignoredPorts.entrySet()) {
                entry.getValue().forEach(portNumber -> ignoredPortsArray.add(
                        codec.encodePort(new MacLearnerKey(entry.getKey(), portNumber, VlanId.NONE), this)
                ));
            }
        }
        root.set("data", ignoredPortsArray);
        return Response.ok(root, MediaType.APPLICATION_JSON_TYPE).build();
    }

    /**
     * Add to ignore ports map.
     *
     * @param ofDeviceId deviceId
     * @param portNumber portNumber
     * @return URI of request
     */
    @POST
    @Path("/ignore-port/{ofDeviceId}/{portNumber}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response addPortToIgnore(@PathParam("ofDeviceId") String ofDeviceId,
                                    @PathParam("portNumber") Integer portNumber) {
        try {
            if (ofDeviceId == null || portNumber == null) {
                throw new IllegalArgumentException(INVALID_PATH_PARAMETERS);
            }
            macLearnerService.addPortToIgnore(DeviceId.deviceId(ofDeviceId),
                    PortNumber.portNumber(portNumber));
            return Response.created(new URI("/add/ignore-port/" +
                    ofDeviceId + PATH_DELIMITER +
                    portNumber)).status(OK).build();
        } catch (URISyntaxException e) {
            log.error("URI Syntax Exception occurred while adding ignore port deviceId: {} portNumber {}",
                    ofDeviceId, portNumber, e);
            return Response.serverError().build();
        }
    }

    /**
     * Remove from ignored ports map.
     *
     * @param ofDeviceId device id
     * @param portNumber port number
     * @return URI of request
     */
    @DELETE
    @Path("/ignore-port/{ofDeviceId}/{portNumber}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response removeFromIgnoredPorts(@PathParam("ofDeviceId") String ofDeviceId,
                                           @PathParam("portNumber") Integer portNumber) {
        try {
            if (ofDeviceId == null || portNumber == null) {
                throw new IllegalArgumentException(INVALID_PATH_PARAMETERS);
            }
            macLearnerService.removeFromIgnoredPorts(DeviceId.deviceId(ofDeviceId),
                    PortNumber.portNumber(portNumber));
            return Response.created(new URI("/remove/ignore-port/" +
                    ofDeviceId + PATH_DELIMITER +
                    portNumber)).status(OK).build();
        } catch (URISyntaxException e) {
            log.error("URISyntaxException occurred while removing ignore port deviceId: {} portNumber {}",
                    ofDeviceId, portNumber, e);
            return Response.serverError().build();
        }
    }

}
