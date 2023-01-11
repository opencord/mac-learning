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
package org.opencord.maclearner.app.impl;

import com.google.common.collect.Sets;
import org.onlab.packet.EthType;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.HostLocation;
import org.onosproject.net.host.DefaultHostDescription;
import org.onosproject.net.host.HostDescription;
import org.onosproject.net.host.HostProvider;
import org.onosproject.net.host.HostProviderRegistry;
import org.onosproject.net.host.HostProviderService;
import org.onosproject.net.host.HostService;
import org.onosproject.net.provider.AbstractProvider;
import org.onosproject.net.provider.ProviderId;
import org.opencord.maclearner.api.MacLearnerHostLocationService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;

import java.util.Collections;
import java.util.Set;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Provider which uses an OpenFlow controller to detect network end-station hosts.
 */
@Component(immediate = true, service = {MacLearnerHostLocationService.class, HostProvider.class})
public class MacLearnerHostProvider extends AbstractProvider
        implements MacLearnerHostLocationService, HostProvider {

    private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostProviderRegistry providerRegistry;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    protected HostProviderService providerService;

    /**
     * Creates an OpenFlow host provider.
     */
    public MacLearnerHostProvider() {
        super(new ProviderId("maclearner", "org.opencord.maclearner.host"));
    }

    @Activate
    public void activate(ComponentContext context) {
        providerService = providerRegistry.register(this);
        log.info("{} is started.", getClass().getSimpleName());
    }

    @Deactivate
    public void deactivate() {
        providerRegistry.unregister(this);
        providerService = null;
        log.info("{} is stopped.", getClass().getSimpleName());
    }

    @Override
    public void triggerProbe(Host host) {
        // Do nothing here
    }

    @Override
    public void createOrUpdateHost(HostId hid, MacAddress srcMac, MacAddress dstMac, VlanId vlan, VlanId innerVlan,
                                   EthType outerTpid, HostLocation hloc, HostLocation auxLoc, IpAddress ip) {
        Set<HostLocation> primaryLocations = Collections.singleton(hloc);
        Set<HostLocation> auxLocations = auxLoc != null ? Collections.singleton(auxLoc) : null;

        HostDescription desc = ip == null || ip.isZero() || ip.isSelfAssigned() ?
                new DefaultHostDescription(srcMac, vlan, primaryLocations, auxLocations, Sets.newHashSet(),
                        innerVlan, outerTpid, false) :
                new DefaultHostDescription(srcMac, vlan, primaryLocations, auxLocations, Sets.newHashSet(ip),
                        innerVlan, outerTpid, false);
        try {
            providerService.hostDetected(hid, desc, false);
        } catch (IllegalStateException e) {
            printHostActionErrorLogs(hid, e);
        }
    }

    @Override
    public void updateHostIp(HostId hid, IpAddress ip) {
        Host host = hostService.getHost(hid);
        if (host == null) {
            log.warn("Fail to update IP for {}. Host does not exist", hid);
            return;
        }

        HostDescription desc = new DefaultHostDescription(hid.mac(), hid.vlanId(),
                host.locations(), Sets.newHashSet(ip), false);
        try {
            providerService.hostDetected(hid, desc, false);
        } catch (IllegalStateException e) {
            printHostActionErrorLogs(hid, e);
        }
    }

    @Override
    public void vanishHost(MacAddress macAddress, VlanId vlanId) {
        HostId hid = HostId.hostId(macAddress, vlanId);
        try {
            providerService.hostVanished(hid);
        } catch (IllegalStateException e) {
            printHostActionErrorLogs(hid, e);
        }
    }

    private void printHostActionErrorLogs(HostId hid, Exception e) {
        log.error("Host {} suppressed due to IllegalStateException", hid);
        log.debug("Exception: ", e);
    }

}
