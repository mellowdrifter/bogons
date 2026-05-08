package bogons

import (
	"net"
	"net/netip"
)

// IsPublicIP checks to ensure that the provided ip is public.
// Deprecated: prefer ValidPublicAddr.
func IsPublicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return ValidPublicAddr(addr.Unmap())
}

// IsPublicIPv4 checks if the IPv4 address is a valid public address.
// Deprecated: prefer ValidPublicAddrV4.
func IsPublicIPv4(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return ValidPublicAddrV4(addr.Unmap())
}

// IsPublicIPv6 checks if the IPv6 address is a valid public address.
// Deprecated: prefer ValidPublicAddrV6.
func IsPublicIPv6(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return ValidPublicAddrV6(addr.Unmap())
}
