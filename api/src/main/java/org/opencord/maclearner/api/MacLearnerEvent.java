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
package org.opencord.maclearner.api;

import org.apache.commons.lang.builder.ToStringBuilder;
import org.onosproject.event.AbstractEvent;

/**
 * Entity that represents Mac Learner events.
 */
public class MacLearnerEvent extends AbstractEvent<MacLearnerEvent.Type, MacLearner> {

    public enum Type {

        /**
         * New entry added to MacLearnerMap.
         */
        ADDED,
        /**
         * An entry removed from MacLearnerMap.
         */
        REMOVED,
    }

    /**
     * Creates an event due to mac learner map update.
     * @param type type of event
     * @param macLearner mac learner object
     */
    public MacLearnerEvent(MacLearnerEvent.Type type, MacLearner macLearner) {
        super(type, macLearner);
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append(super.toString())
                .toString();
    }

}
