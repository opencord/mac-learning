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

import org.onlab.packet.MacAddress;

import java.util.Objects;

/**
 * Value of Mac Address Map which keeps a timestamp via Mac Address.
 */
public class MacLearnerValue {

    private MacAddress macAddress;
    private long timestamp;

    public MacAddress getMacAddress() {
        return macAddress;
    }

    public void setMacAddress(MacAddress macAddress) {
        this.macAddress = macAddress;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public MacLearnerValue(MacAddress macAddress, long timestamp) {
        this.macAddress = macAddress;
        this.timestamp = timestamp;
    }

    @Override
    public String toString() {
        return "MacLearnerValue{" +
                "macAddress=" + macAddress +
                ", timestamp=" + timestamp +
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
        MacLearnerValue that = (MacLearnerValue) o;
        return timestamp == that.timestamp &&
                Objects.equals(macAddress, that.macAddress);
    }

    @Override
    public int hashCode() {
        return Objects.hash(macAddress, timestamp);
    }

}
