# tritiumbridgetools

[![Build Status](https://travis-ci.org/karlding/tritiumbridgetools.svg?branch=master)](https://travis-ci.org/karlding/tritiumbridgetools)

tools for working with the Tritium CAN-Ethernet bridge

# Usage

```bash
# Find the interface you connected the Tritium CAN-Ethernet bridge to
ifconfig

# Assign yourself an IPv4 address on the same subnet
sudo ifconfig enp0s25 up 192.168.10.102

# Bring up a vcan interface
sudo modprobe can
sudo modprobe can_raw
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# Proxy data
# We write data from bus 13 on vcan0
./tritiumbridgetools proxy \
  --transport=udp \
  --config=configs/example-01.toml

# Proxy multiple buses instead if we have multiple bridges sending
./tritiumbridgetools proxy \
  --transport=udp \
  --config=configs/example-02.toml

# Proxy over TCP instead of UDP
./tritiumbridgetools proxy \
  --transport=tcp \
  --config=configs/example-01.toml
```

## Known limitations

* Currently, we require a 1:1 mapping between bridges and VCAN networks,
regardless of network interface the bridge is connected to
* All bridges in use must have a unique bus number, regardless of network
interface the bridge is connected to
* No discovery and setup based on heartbeat packets
* All bridges must be connected to the same Network Interface


## TOML config file

### Example 01: Map a Tritium CAN-Ethernet bridge to a vcan network

This assumes that:

* Your bridge has the static ip `192.168.10.101`
* Your network interface is called `enp0s25`
* The SocketCAN interface you wish to forward onto is called `vcan0`

```toml
[[bridge]]
ip = "192.168.10.101"
id = 13
network_interface = "enp0s25"
vcan = "vcan0"
```

### Example 02: Map multiple bridges on one interface to separate vcan networks

```toml
[[bridge]]
ip = "169.254.253.192"
id = 13
network_interface = "enp0s25"
vcan = "vcan0"

[[bridge]]
ip = "169.254.253.193"
id = 14
network_interface = "enp0s25"
vcan = "vcan1"
```
