![test](https://github.com/yoshd/stun_client/workflows/Test/badge.svg)

# stun_client

This is a simple async_std based asynchronous STUN client library.
At the moment only some features of [RFC8489](https://tools.ietf.org/html/rfc8489) are implemented and only simple binding requests are possible.

It also supports the OTHER-ADDRESS and CHANGE-REQUEST attributes for [RFC5780](https://tools.ietf.org/html/rfc5780) -based NAT Behavior Discovery.

## Examples

[Simple STUN Binding](examples/stun_client.rs)
