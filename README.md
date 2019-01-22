# tritiumbridgetools

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

# Dump data
# We write data from bus 13 on vcan0
./tritiumbridgetools enp0s25 vcan0=13
```
