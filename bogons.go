package bogons

import "net"

// ValidASN checks whether an ASN is valid.
// No private or reserved ASNs are valid.
func ValidASN(asn uint32) bool {
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

// ValidIP just checks whether the strings parses into
// either an IPv4 or IPv6 address. It must also be public.
func ValidIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	// Private IPs are not valid
	return IsPublicIP(parsed)
}

// IsPublicIP checks to ensure that the provided ip is public. Either IPv4 or IPv6 can be used as input.
func IsPublicIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return IsPublicIPv4(ip4)
	}
	return IsPublicIPv6(ip)

}

// IsPublicIPv4 checks if the IPv4 address is a valid public address.
func IsPublicIPv4(ip net.IP) bool {
	if !ip.IsGlobalUnicast() {
		return false
	}

	switch {
	// 0.x.x.x/8
	case ip[0] == 0:
		return false
	// loopbacks
	case ip[0] == 127:
		return false
	// rfc1918
	case ip[0] == 10:
		return false
	// rfc1918
	case ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31:
		return false
	// rfc1918
	case ip[0] == 192 && ip[1] == 168:
		return false
	// rfc6598
	case ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127:
		return false
	// rfc3927
	case ip[0] == 169 && ip[1] == 254:
		return false
	// rfc6980 && rfc5737
	case ip[0] == 192 && ip[1] == 0 && (ip[2] == 0 || ip[2] == 2):
		return false
	// rfc5737
	case ip[0] == 198 && ip[1] == 51 && ip[2] == 100:
		return false
	// rfc5737
	case ip[0] == 203 && ip[1] == 0 && ip[2] == 113:
		return false
	// class D,E
	case ip[0] >= 224:
		return false
	}

	return true

}

// IsPublicIPv6 checks if the IPv6 address is a valid public address.
func IsPublicIPv6(ip net.IP) bool {
	if !ip.IsGlobalUnicast() {
		return false
	}
	switch {
	// Teredo tunnels 2001::/32
	case ip[0] == 32 && ip[1] == 1 && ip[2] == 0 && ip[3] == 0:
		return false
	// documentation 2001:db8::/32
	case ip[0] == 32 && ip[1] == 1 && ip[2] == 13 && ip[3] == 184:
		return false
	}
	// Besides the above, as long as the prefix sits inside 2000::/3 it's public
	return ip[0] >= 32 && ip[0] <= 63
}
