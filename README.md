# tritiumbridgetools

tools for working with the Tritium CAN-Ethernet bridge

# Usage

```bash
# Find the interface you connected the Tritium CAN-Ethernet bridge to
ifconfig

# Assign yourself an IPv4 address
sudo ifconfig enp0s25 up 169.254.253.191

# Dump data
./tritiumbridgetools enp0s25
```
