# bogons

[![Go Reference](https://pkg.go.dev/badge/github.com/mellowdrifter/bogons.svg)](https://pkg.go.dev/github.com/mellowdrifter/bogons)
[![Go Report Card](https://goreportcard.com/badge/github.com/mellowdrifter/bogons)](https://goreportcard.com/report/github.com/mellowdrifter/bogons)

A lightweight Go library for identifying "bogon" IP addresses and Autonomous System Numbers (ASNs). Bogons are IP ranges or ASNs that should not be visible on the public internet, including private, reserved, and unallocated space.

## Features

- **IP Validation**: Check if an IPv4 or IPv6 address is a valid public address.
- **ASN Validation**: Verify if an ASN is a valid public ASN (excludes private and reserved ranges).
- **RFC Compliant**: Based on various RFCs (RFC1918, RFC6598, RFC5737, etc.).
- **Zero Dependencies**: Uses only the standard library.

## Installation

```bash
go get github.com/mellowdrifter/bogons
```

## Usage

### IP Validation

Check if an IP string is a valid public address:

```go
package main

import (
	"fmt"
	"github.com/mellowdrifter/bogons"
)

func main() {
	fmt.Println(bogons.ValidPublicIP("1.1.1.1"))    // Output: true
	fmt.Println(bogons.ValidPublicIP("10.0.0.1"))   // Output: false (RFC1918)
	fmt.Println(bogons.ValidPublicIP("2001:db8::1")) // Output: false (Documentation)
}
```

### ASN Validation

Check if an ASN is a valid public Autonomous System Number:

```go
package main

import (
	"fmt"
	"github.com/mellowdrifter/bogons"
)

func main() {
	fmt.Println(bogons.ValidPublicASN(15169)) // Output: true (Google)
	fmt.Println(bogons.ValidPublicASN(64512)) // Output: false (Private Use)
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the same terms as Go itself.