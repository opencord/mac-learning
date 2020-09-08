ONOS MAC Learner Application
=====================================
MAC Learner is an ONOS application that examines DISCOVER or REQUEST type DHCP packets and
keeps the MAC address temporarily according to the device, port and vlanId information obtained from
these packets. If the package has a single tag, VlanVID is used;
if it is a double tag, QinqVID is used as vlanId.

Functionalities
---------------
- MAC Learner has REST API and CLI integration. You can access and modify MAC Address map via these.

- By defining ports to the Ignored Port Map,
it can be ensured that DHCP packets from these ports are not taken into account.

Parameters
---------------
* __cacheDurationSec__ - MAC Mappings are held with a timestamp and scheduled executor running in the
background that clears expired mappings(exist more than cacheDuration). The operating frequency of
this executor can be set with this parameter. By default, it is 86400(1 day).

* __autoClearMacMapping__ - By enabling this parameter, the relevant mappings can be cleared
automatically with DEVICE_REMOVED and PORT_REMOVED device events. By default, it is disabled.