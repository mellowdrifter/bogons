# bogons

[![Go Reference](https://pkg.go.dev/badge/github.com/mellowdrifter/bogons.svg)](https://pkg.go.dev/github.com/mellowdrifter/bogons)
[![Go Report Card](https://goreportcard.com/badge/github.com/mellowdrifter/bogons)](https://goreportcard.com/report/github.com/mellowdrifter/bogons)

A lightweight Go library for identifying "bogon" IP addresses and Autonomous System Numbers (ASNs). Bogons are IP ranges or ASNs that should not be visible on the public internet, including private, reserved, and unallocated space.

## Features

- **IP Validation**: Check if an IPv4 or IPv6 address is a valid public address, and optionally retrieve the RFC reason.
- **Prefix / Subnet Validation**: Test whether a prefix sits in publicly routable space (`CheckPrefix`), or check strict BGP routable boundaries (`ValidPublicPrefix`).
- **ASN Validation**: Verify if an ASN is a valid public ASN, with RFC reason for reserved and private ranges.
- **RFC Compliant**: Up-to-date with RFC 1122, RFC 1918, RFC 6598, RFC 5737, RFC 7526, RFC 7535, RFC 7450, RFC 7534, RFC 9385, RFC 8880, RFC 7725, RFC 8155, RFC 6483, RFC 7300, etc.
- **Zero Dependencies**: Uses only the standard library (`net/netip`).

## Installation

```bash
go get github.com/mellowdrifter/bogons
```

## Usage

### IP Validation with Reasons

Use `CheckIP` (or `CheckAddr`) to check if an address is public and receive the reason/RFC if it is a bogon:

```go
package main

import (
	"fmt"
	"github.com/mellowdrifter/bogons"
)

func main() {
	valid, reason := bogons.CheckIP("1.1.1.1")
	fmt.Printf("1.1.1.1: valid=%v, reason=%q\n", valid, reason)
	// Output: 1.1.1.1: valid=true, reason=""

	valid, reason = bogons.CheckIP("10.0.0.1")
	fmt.Printf("10.0.0.1: valid=%v, reason=%q\n", valid, reason)
	// Output: 10.0.0.1: valid=false, reason="RFC 1918 (Private-Use)"

	valid, reason = bogons.CheckIP("2001:db8::1")
	fmt.Printf("2001:db8::1: valid=%v, reason=%q\n", valid, reason)
	// Output: 2001:db8::1: valid=false, reason="RFC 3849 (Documentation)"
}
```

Boolean-only checks remain available via `ValidPublicIP`, `ValidPublicAddr`, etc.

### Prefix & Subnet Validation

Use `CheckPrefix` to determine if a subnet sits within public space (ignoring BGP route boundary filters):

```go
prefix := netip.MustParsePrefix("8.8.8.0/25")
valid, reason := bogons.CheckPrefix(prefix) // valid=true, reason=""

privPrefix := netip.MustParsePrefix("192.168.1.0/24")
valid, reason := bogons.CheckPrefix(privPrefix) // valid=false, reason="RFC 1918 (Private-Use)"
```

To enforce BGP routing announcement limits (`/8`-`/24` for IPv4, `/16`-`/48` for IPv6), use `ValidPublicPrefix`.

### ASN Validation with Reasons

Check if an ASN is a valid public Autonomous System Number:

```go
package main

import (
	"fmt"
	"github.com/mellowdrifter/bogons"
)

func main() {
	valid, reason := bogons.CheckASN(15169)
	fmt.Printf("AS15169: valid=%v, reason=%q\n", valid, reason)
	// Output: AS15169: valid=true, reason=""

	valid, reason = bogons.CheckASN(64512)
	fmt.Printf("AS64512: valid=%v, reason=%q\n", valid, reason)
	// Output: AS64512: valid=false, reason="RFC 1930 / RFC 6996 (Private-Use 16-bit)"
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the same terms as Go itself.