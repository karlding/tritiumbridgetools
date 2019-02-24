# Summary

This RFC suggests a way of implementing Network Auto Discovery for the bridge.

Auto Discovery is basically a way to have the program intelligently discover
the bus topology, without requiring a TOML file to be specified.

# Motivation

This is intended to make dealing with dynamic IP addresses (and adding/removing nodes)
easier.

## Detailed Design

The Tritium packet contains the following information:

```c
// +-----------------------------+
// | Padding (8 bits)            | 0
// +-----------------------------+
// | Bus Identifier (56 bits)    | 1 - 7
// +-----------------------------+
// | Padding (8 bits)            | 8
// +-----------------------------+
// | Client Identifier (56 bits) | 9 - 15
// +-----------------------------+
// | CAN ID (32 bits)            | 16 - 19
// +-----------------------------+
// | Flags (8 bits)              | 20
// +-----------------------------+
// | Length (8 bits)             | 21
// +-----------------------------+
// | Data (64 bits)              | 22 - 29
// +-----------------------------+
```

Auto Discovery uses the `Bus Identifier` field in order to select the
appropriate `vcan` interface, by assuming a 1:1 mapping. Therefore, the
`Bus Identifier` field must be unique for each bridge that is added on your
bus.

### UDP

This goroutine should be run on each bound interface:

```
receive UDP packet

if packet type is a heartbeat packet:
  if source ip has not been seen:
    attempt to bind to vcan{bus number} SocketCAN interface
    socketMap[bus number] = SocketCAN interface

    start goroutine to forward SocketCAN onto this interface via UDP

if packet type should be forwarded
  get bus number from packet      
  forward packet onto socketMap[bus number]
```

### TCP

On TCP, it is slightly more complex due to the connection requirements.

```
receive UDP packet

if packet type is a heartbeat packet:
  if source ip has not been seen:
    attempt to bind to vcan{bus number} SocketCAN interface
    socketMap[bus number] = SocketCAN interface

    start goroutine to forward TCP onto the SocketCAN interface
    start goroutine to forward SocketCAN onto this interface via TCP
```

# Drawbacks

This is slightly more complicated than the current implementation. Because
there is no way of mapping arbitrary networks, it requires that `vcan` networks
corresponding to the Bus ID exist, as the only way to forward messages is to
forward to the `vcan` network with the same Bus ID (without requiring some
mapping, which defeats the purpose of this). As such, this introduces "magic"
that would otherwise be avoided.

# Alternatives

Currently the program parses a TOML file and describing the bus topology, and
uses that to correctly route CAN messages onto the proper bus. We could simply
refuse to support devices that are not defined within the TOML, and use this
as the source of truth.

We can also remove the IP addresses from the TOML, and rely completely on the
Bus Number. This would be possible by implementing portions of this RFC in
order to support Auto Discovery, and we could stop the implementation there.

# Unresolved Questions

Do we want to handle the same bus number on a different interface?

If this is the case, then we can use a composite key consisting of the
`(IP, Interface)` pair, which would serve as the unique identifier in place of
the Bus Number.
