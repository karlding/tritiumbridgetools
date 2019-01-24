# tritiumbridgetools

[![Build Status](https://travis-ci.org/karlding/tritiumbridgetools.svg?branch=master)](https://travis-ci.org/karlding/tritiumbridgetools)

tools for working with the Tritium CAN-Ethernet bridge

# Usage

```bash
# Find the interface you connected the Tritium CAN-Ethernet bridge to
ifconfig

# Assign yourself an IPv4 address on the same subnet
sudo ifconfig enp0s25 up 169.254.253.191

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
  --interface=enp0s25 \
  --bridge "vcan0=13"

# Proxy multiple buses instead if we have multiple bridges sending
./tritiumbridgetools proxy \
  --transport=udp \
  --interface=enp0s25 \
  --bridge "vcan0=13","vcan1=14"

# Proxy over TCP instead of UDP
./tritiumbridgetools proxy \
  --transport=tcp \
  --bridgeaddress=169.254.253.192 \
  --interface=enp0s25 \
  --bridge "vcan0=13","vcan1=14"

# Dump data to stdout in candump format
./tritiumbridgetools dump \
  --transport=udp \
  --interface=enp0s25
```
