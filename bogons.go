package bogons

import "net/netip"

// IPv4 bogon prefixes
var (
	v4This       = netip.MustParsePrefix("0.0.0.0/8")       // RFC 1122
	v4Loopback   = netip.MustParsePrefix("127.0.0.0/8")     // RFC 1122
	v4RFC1918a   = netip.MustParsePrefix("10.0.0.0/8")      // RFC 1918
	v4RFC1918b   = netip.MustParsePrefix("172.16.0.0/12")   // RFC 1918
	v4RFC1918c   = netip.MustParsePrefix("192.168.0.0/16")  // RFC 1918
	v4RFC6598    = netip.MustParsePrefix("100.64.0.0/10")   // RFC 6598 (shared address)
	v4LinkLocal  = netip.MustParsePrefix("169.254.0.0/16")  // RFC 3927
	v4IANA1      = netip.MustParsePrefix("192.0.0.0/24")    // RFC 6890 (IANA special purpose)
	v4Doc1       = netip.MustParsePrefix("192.0.2.0/24")    // RFC 5737
	v4Doc2       = netip.MustParsePrefix("198.51.100.0/24") // RFC 5737
	v4Doc3       = netip.MustParsePrefix("203.0.113.0/24")  // RFC 5737
	v4Benchmarks = netip.MustParsePrefix("198.18.0.0/15")   // RFC 2544
	v4Multicast  = netip.MustParsePrefix("224.0.0.0/4")     // RFC 1112 (Class D)
	v4ClassE     = netip.MustParsePrefix("240.0.0.0/4")     // RFC 1112 (Class E)
)

// IPv6 bogon prefixes
var (
	v6IETF       = netip.MustParsePrefix("2001::/23")      // RFC 2928 (IETF Protocol Assignments) - covers Teredo, Benchmarks, ORCHID, etc.
	v6Doc        = netip.MustParsePrefix("2001:db8::/32")  // RFC 3849
	v66to4       = netip.MustParsePrefix("2002::/16")      // RFC 3056
	v6Discard    = netip.MustParsePrefix("100::/64")       // RFC 6666
	v6NAT64      = netip.MustParsePrefix("64:ff9b::/96")   // RFC 6052
	v6NAT64Local = netip.MustParsePrefix("64:ff9b:1::/48") // RFC 8215
	v66bone      = netip.MustParsePrefix("3ffe::/16")      // RFC 3701 (deprecated)
)

// ValidPublicASN checks whether an ASN is valid.
// No private or reserved ASNs are valid.
func ValidPublicASN(asn uint32) bool {
	switch {
	case asn == 0: // RFC6483, RFC7607
		return false
	case asn == 23456: // RFC6793
		return false
	case asn >= 64496 && asn <= 64511: // RFC5398
		return false
	case asn >= 64512 && asn <= 65534: // RFC1930, RFC6996
		return false
	case asn == 65535: // RFC7300
		return false
	case asn >= 65536 && asn <= 65551: //RFC4893, RFC5398
		return false
	case asn >= 65552 && asn <= 131071:
		return false
	case asn >= 4200000000 && asn <= 4294967294: //RFC6996
		return false
	case asn == 4294967295: // RFC7300
		return false
	}

	return true
}

// ValidPublicIP reports whether the string s parses as a publicly routable
// IPv4 or IPv6 address.
func ValidPublicIP(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return ValidPublicAddr(addr)
}

// ValidPublicAddr reports whether addr is a publicly routable address.
// Both IPv4 and IPv6 are supported. Mapped IPv4-in-IPv6 addresses are
// treated as IPv4.
func ValidPublicAddr(addr netip.Addr) bool {
	addr = addr.Unmap() // normalise IPv4-in-IPv6 to plain IPv4
	if !addr.IsValid() {
		return false
	}
	if addr.Is4() {
		return ValidPublicAddrV4(addr)
	}
	return ValidPublicAddrV6(addr)
}

// ValidPublicAddrV4 reports whether addr is a publicly routable IPv4 address.
func ValidPublicAddrV4(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	if !addr.IsGlobalUnicast() {
		return false
	}
	for _, bogon := range []netip.Prefix{
		v4This, v4Loopback, v4RFC1918a, v4RFC1918b, v4RFC1918c,
		v4RFC6598, v4LinkLocal, v4IANA1, v4Doc1, v4Doc2, v4Doc3,
		v4Benchmarks, v4Multicast, v4ClassE,
	} {
		if bogon.Contains(addr) {
			return false
		}
	}
	return true
}

// ValidPublicAddrV6 reports whether addr is a publicly routable IPv6 address.
// ULA addresses (fc00::/7) are rejected implicitly via IsGlobalUnicast.
// Only addresses within 2000::/3 are considered publicly routable.
func ValidPublicAddrV6(addr netip.Addr) bool {
	if !addr.Is6() {
		return false
	}
	if !addr.IsGlobalUnicast() {
		return false // catches ULA (fc00::/7), loopback, link-local, etc.
	}
	for _, bogon := range []netip.Prefix{
		v6IETF, v6Doc, v66to4,
		v6Discard, v6NAT64, v6NAT64Local, v66bone,
	} {
		if bogon.Contains(addr) {
			return false
		}
	}
	// Only 2000::/3 is globally routable
	a := addr.As16()
	return a[0] >= 0x20 && a[0] <= 0x3f
}

// ValidPublicPrefix reports whether prefix is a publicly routable, correctly
// bounded network prefix suitable for BGP announcement.
//
// IPv4: prefix length must be between /8 and /24 (inclusive).
// IPv6: prefix length must be between /16 and /48 (inclusive).
//
// Prefixes with host bits set (i.e. not normalised) are rejected.
func ValidPublicPrefix(prefix netip.Prefix) bool {
	// Must be normalised — no host bits set
	if prefix != prefix.Masked() {
		return false
	}

	addr := prefix.Addr()
	bits := prefix.Bits()

	if addr.Is4() {
		if bits < 8 || bits > 24 {
			return false
		}
		return ValidPublicAddrV4(addr)
	}

	// IPv6
	if bits < 16 || bits > 48 {
		return false
	}
	return ValidPublicAddrV6(addr)
}
