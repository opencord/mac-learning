/*
 * Copyright 2019-present Open Networking Foundation
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

/**
 * Constants for default values of configurable properties.
 */
public final class OsgiPropertyConstants {

    private OsgiPropertyConstants() {
    }

    public static final String CACHE_DURATION = "cacheDurationSec";
    public static final int CACHE_DURATION_DEFAULT = 86400; // 1 day

    public static final String AUTO_CLEAR_MAC_MAPPING = "autoClearMacMapping";
    public static final boolean AUTO_CLEAR_MAC_MAPPING_DEFAULT = false;

    public static final String ENABLE_DHCP_FORWARD = "enableDhcpForward";
    public static final boolean ENABLE_DHCP_FORWARD_DEFAULT = false;

}
