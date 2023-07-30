![test](https://github.com/yoshd/stun-client/workflows/Test/badge.svg)

# stun-client

This is a simple async_std based asynchronous STUN client library.
At the moment only some features of [RFC8489](https://tools.ietf.org/html/rfc8489) are implemented and only simple binding requests are possible.

It also supports the OTHER-ADDRESS and CHANGE-REQUEST attributes for [RFC5780](https://tools.ietf.org/html/rfc5780) -based NAT Behavior Discovery.

[Install](https://crates.io/crates/stun-client)

[Documentation](https://docs.rs/stun-client/)

## Examples

- [Simple STUN Binding](examples/stun_client.rs)
- [NAT Behavior Discovery](examples/nat_behavior_discovery.rs)
- [UDP Hole Punching](examples/udp_hole_punching.rs)

# Running on Windows

Due to the requirements of the dependency library libpnet, additional steps are needed.
Please refer to the following.

https://github.com/libpnet/libpnet#windows
