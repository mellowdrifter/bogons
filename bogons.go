package bogons

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type prefixRule struct {
	prefix netip.Prefix
	reason string
}

type asRule struct {
	start  uint32
	end    uint32
	reason string
}

// IPv4 bogon rules with RFC descriptions
var v4BogonRules = []prefixRule{
	{netip.MustParsePrefix("0.0.0.0/8"), "RFC 1122 (This Host on This Network)"},
	{netip.MustParsePrefix("10.0.0.0/8"), "RFC 1918 (Private-Use)"},
	{netip.MustParsePrefix("100.64.0.0/10"), "RFC 6598 (Shared Address Space / CGNAT)"},
	{netip.MustParsePrefix("127.0.0.0/8"), "RFC 1122 (Loopback)"},
	{netip.MustParsePrefix("169.254.0.0/16"), "RFC 3927 (Link-Local)"},
	{netip.MustParsePrefix("172.16.0.0/12"), "RFC 1918 (Private-Use)"},
	// Specific 192.0.0.0/24 sub-allocations
	{netip.MustParsePrefix("192.0.0.170/31"), "RFC 8880 (NAT64/DNS64 Discovery)"},
	{netip.MustParsePrefix("192.0.0.10/32"), "RFC 8155 (TURN Anycast)"},
	{netip.MustParsePrefix("192.0.0.9/32"), "RFC 7725 (PCP Anycast)"},
	{netip.MustParsePrefix("192.0.0.8/32"), "RFC 7600 (IPv4 Dummy Address)"},
	{netip.MustParsePrefix("192.0.0.0/29"), "RFC 6333 / RFC 7335 (DS-Lite / Dual-Stack Continuity)"},
	{netip.MustParsePrefix("192.0.0.0/24"), "RFC 6890 (IETF Protocol Assignments)"},
	{netip.MustParsePrefix("192.0.2.0/24"), "RFC 5737 (Documentation TEST-NET-1)"},
	{netip.MustParsePrefix("192.31.196.0/24"), "RFC 7535 (AS112-v4)"},
	{netip.MustParsePrefix("192.52.193.0/24"), "RFC 7450 (Automatic Multicast Tunneling - AMT)"},
	{netip.MustParsePrefix("192.88.99.0/24"), "RFC 7526 (6to4 Relay Anycast - Deprecated)"},
	{netip.MustParsePrefix("192.168.0.0/16"), "RFC 1918 (Private-Use)"},
	{netip.MustParsePrefix("198.18.0.0/15"), "RFC 2544 (Benchmarking)"},
	{netip.MustParsePrefix("198.51.100.0/24"), "RFC 5737 (Documentation TEST-NET-2)"},
	{netip.MustParsePrefix("203.0.113.0/24"), "RFC 5737 (Documentation TEST-NET-3)"},
	{netip.MustParsePrefix("224.0.0.0/4"), "RFC 1112 (Multicast)"},
	{netip.MustParsePrefix("255.255.255.255/32"), "RFC 919 / RFC 8190 (Limited Broadcast)"},
	{netip.MustParsePrefix("240.0.0.0/4"), "RFC 1112 (Reserved / Former Class E)"},
}

// IPv6 bogon rules with RFC descriptions
var v6BogonRules = []prefixRule{
	{netip.MustParsePrefix("2001:db8::/32"), "RFC 3849 (Documentation)"},
	{netip.MustParsePrefix("2001::/32"), "RFC 4380 (Teredo)"},
	{netip.MustParsePrefix("2001:1::1/128"), "RFC 7723 (PCP Anycast)"},
	{netip.MustParsePrefix("2001:1::2/128"), "RFC 8155 (TURN Anycast)"},
	{netip.MustParsePrefix("2001:2::/48"), "RFC 5180 / RFC 9006 (Benchmarking)"},
	{netip.MustParsePrefix("2001:3::/32"), "RFC 7450 (Automatic Multicast Tunneling - AMT)"},
	{netip.MustParsePrefix("2001:4:112::/48"), "RFC 7535 (AS112-v6)"},
	{netip.MustParsePrefix("2001:10::/28"), "RFC 4843 (Deprecated ORCHID)"},
	{netip.MustParsePrefix("2001:20::/28"), "RFC 7343 (ORCHIDv2)"},
	{netip.MustParsePrefix("2001:30::/28"), "RFC 9385 (Drone Remote ID)"},
	{netip.MustParsePrefix("2001::/23"), "RFC 2928 (IETF Protocol Assignments)"},
	{netip.MustParsePrefix("2002::/16"), "RFC 3056 / RFC 7526 (6to4 - Deprecated)"},
	{netip.MustParsePrefix("2620:4f:8000::/48"), "RFC 7534 (Direct Delegation AS112)"},
	{netip.MustParsePrefix("64:ff9b:1::/48"), "RFC 8215 (Local-Use IPv4/IPv6 Translation)"},
	{netip.MustParsePrefix("64:ff9b::/96"), "RFC 6052 (IPv4/IPv6 Translation)"},
	{netip.MustParsePrefix("100::/64"), "RFC 6666 (Discard-Only)"},
	{netip.MustParsePrefix("3ffe::/16"), "RFC 3701 (6bone - Deprecated / Returned)"},
}

// ASN bogon rules
var asRules = []asRule{
	{0, 0, "RFC 6483 / RFC 7607 (Reserved ASN 0)"},
	{23456, 23456, "RFC 6793 (AS_TRANS 4-Byte Transition)"},
	{64496, 64511, "RFC 5398 (Documentation 16-bit)"},
	{64512, 65534, "RFC 1930 / RFC 6996 (Private-Use 16-bit)"},
	{65535, 65535, "RFC 7300 (Reserved 16-bit Last ASN)"},
	{65536, 65551, "RFC 5398 (Documentation 32-bit)"},
	{65552, 131071, "RFC 7249 / IANA (Reserved 32-bit)"},
	{4200000000, 4294967294, "RFC 6996 (Private-Use 32-bit)"},
	{4294967295, 4294967295, "RFC 7300 (Reserved 32-bit Last ASN)"},
}

// CheckASN checks whether an ASN is valid and publicly routable.
// If valid, returns true and an empty reason. If bogon/reserved, returns false and the RFC/reason.
func CheckASN(asn uint32) (bool, string) {
	for _, rule := range asRules {
		if asn >= rule.start && asn <= rule.end {
			return false, rule.reason
		}
	}
	return true, ""
}

// ValidPublicASN checks whether an ASN is valid and publicly routable.
// Deprecated / convenience wrapper around CheckASN.
func ValidPublicASN(asn uint32) bool {
	valid, _ := CheckASN(asn)
	return valid
}

// ParseASN parses a string representation of an ASN.
// It accepts decimal strings ("15169"), strings with leading "AS"/"as" ("AS15169"),
// and 4-byte asdot notation ("1.0").
func ParseASN(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "AS") || strings.HasPrefix(s, "as") || strings.HasPrefix(s, "As") || strings.HasPrefix(s, "aS") {
		s = s[2:]
	}
	if s == "" {
		return 0, fmt.Errorf("empty ASN string")
	}

	// Check asdot notation (e.g. 1.0)
	if strings.Contains(s, ".") {
		parts := strings.Split(s, ".")
		if len(parts) != 2 {
			return 0, fmt.Errorf("invalid asdot syntax: %s", s)
		}
		high, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return 0, fmt.Errorf("invalid asdot high order 16-bit: %w", err)
		}
		low, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return 0, fmt.Errorf("invalid asdot low order 16-bit: %w", err)
		}
		return uint32(high<<16 | low), nil
	}

	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

// CheckASNString parses and checks whether an ASN string is valid and publicly routable.
// Accepts asplain ("15169"), with "AS" prefix ("AS15169"), or asdot ("1.0").
// If valid, returns true and an empty reason. If invalid syntax or a bogon, returns false and the reason.
func CheckASNString(s string) (bool, string) {
	asn, err := ParseASN(s)
	if err != nil {
		return false, "Invalid ASN syntax"
	}
	return CheckASN(asn)
}

// ValidPublicASNString reports whether the string s is a valid publicly routable ASN.
func ValidPublicASNString(s string) bool {
	valid, _ := CheckASNString(s)
	return valid
}

// CheckIP reports whether the string parses as a publicly routable IP address.
// If valid and public, returns true and an empty reason string.
// If invalid syntax or a bogon, returns false and the corresponding reason/RFC.
func CheckIP(ip string) (bool, string) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false, "Invalid IP address syntax"
	}
	return CheckAddr(addr)
}

// ValidPublicIP reports whether the string parses as a publicly routable IP address.
func ValidPublicIP(ip string) bool {
	valid, _ := CheckIP(ip)
	return valid
}

// CheckAddr reports whether addr is a publicly routable address.
// Both IPv4 and IPv6 are supported. Mapped IPv4-in-IPv6 addresses are unmapped to IPv4.
// If public, returns true and "". If a bogon, returns false and the RFC/reason.
func CheckAddr(addr netip.Addr) (bool, string) {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return false, "Invalid IP address"
	}
	if addr.Is4() {
		return CheckAddrV4(addr)
	}
	return CheckAddrV6(addr)
}

// ValidPublicAddr reports whether addr is a publicly routable address.
func ValidPublicAddr(addr netip.Addr) bool {
	valid, _ := CheckAddr(addr)
	return valid
}

// CheckAddrV4 reports whether addr is a publicly routable IPv4 address.
func CheckAddrV4(addr netip.Addr) (bool, string) {
	if !addr.Is4() {
		return false, "Not an IPv4 address"
	}
	if !addr.IsValid() {
		return false, "Invalid IPv4 address"
	}
	for _, rule := range v4BogonRules {
		if rule.prefix.Contains(addr) {
			return false, rule.reason
		}
	}
	if !addr.IsGlobalUnicast() {
		if addr.IsLoopback() {
			return false, "RFC 1122 (Loopback)"
		}
		if addr.IsLinkLocalUnicast() {
			return false, "RFC 3927 (Link-Local)"
		}
		if addr.IsMulticast() {
			return false, "RFC 1112 (Multicast)"
		}
		return false, "Not global unicast"
	}
	return true, ""
}

// ValidPublicAddrV4 reports whether addr is a publicly routable IPv4 address.
func ValidPublicAddrV4(addr netip.Addr) bool {
	valid, _ := CheckAddrV4(addr)
	return valid
}

// CheckAddrV6 reports whether addr is a publicly routable IPv6 address.
func CheckAddrV6(addr netip.Addr) (bool, string) {
	if !addr.Is6() {
		return false, "Not an IPv6 address"
	}
	if !addr.IsValid() {
		return false, "Invalid IPv6 address"
	}

	// Check explicit special-purpose rules
	for _, rule := range v6BogonRules {
		if rule.prefix.Contains(addr) {
			return false, rule.reason
		}
	}

	// Check special address types via netip.Addr methods
	if addr.IsLoopback() {
		return false, "RFC 4291 (Loopback)"
	}
	if addr.IsUnspecified() {
		return false, "RFC 4291 (Unspecified)"
	}
	if addr.IsLinkLocalUnicast() {
		return false, "RFC 4291 (Link-Local)"
	}
	if addr.IsPrivate() {
		return false, "RFC 4193 (Unique Local Address / ULA)"
	}
	if addr.IsMulticast() {
		return false, "RFC 4291 (Multicast)"
	}

	// Only 2000::/3 is globally routable
	a := addr.As16()
	if a[0] < 0x20 || a[0] > 0x3f {
		return false, "RFC 4291 (IANA Unallocated / Outside 2000::/3 Global Unicast)"
	}

	return true, ""
}

// ValidPublicAddrV6 reports whether addr is a publicly routable IPv6 address.
func ValidPublicAddrV6(addr netip.Addr) bool {
	valid, _ := CheckAddrV6(addr)
	return valid
}

// CheckPrefix reports whether the prefix sits within publicly routable space.
// It checks whether the prefix or its network address falls inside any bogon subnet.
// Unlike ValidPublicPrefix, it does not enforce BGP prefix length limits (/8-/24 or /16-/48).
func CheckPrefix(prefix netip.Prefix) (bool, string) {
	if !prefix.IsValid() {
		return false, "Invalid prefix"
	}
	addr := prefix.Addr().Unmap()
	return CheckAddr(addr)
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

	addr := prefix.Addr().Unmap()
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
