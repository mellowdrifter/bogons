package bogons_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/mellowdrifter/bogons"
)

type ipTestCase struct {
	ip   string
	want bool
	rfc  string
}

var ipTests = []ipTestCase{
	// IPv4 Global Unicast (Valid)
	{"1.1.1.1", true, "Global Unicast"},
	{"8.8.8.8", true, "Google DNS"},
	{"192.0.1.1", true, "Public IANA"},

	// IPv4 Bogons
	{"0.0.0.1", false, "RFC 1122 (This Network)"},
	{"127.0.0.1", false, "RFC 1122 (Loopback)"},
	{"10.1.2.3", false, "RFC 1918 (Private)"},
	{"172.16.1.1", false, "RFC 1918 (Private)"},
	{"172.31.255.255", false, "RFC 1918 (Private)"},
	{"192.168.1.1", false, "RFC 1918 (Private)"},
	{"100.64.0.1", false, "RFC 6598 (Shared Address)"},
	{"169.254.1.1", false, "RFC 3927 (Link Local)"},
	{"192.0.0.1", false, "RFC 6890 (IANA Special)"},
	{"192.0.2.1", false, "RFC 5737 (Documentation)"},
	{"198.51.100.1", false, "RFC 5737 (Documentation)"},
	{"203.0.113.1", false, "RFC 5737 (Documentation)"},
	{"198.18.0.1", false, "RFC 2544 (Benchmarks)"},
	{"198.19.255.255", false, "RFC 2544 (Benchmarks)"},
	{"224.0.0.1", false, "RFC 1112 (Multicast)"},
	{"240.0.0.1", false, "RFC 1112 (Class E / Reserved)"},
	{"255.255.255.255", false, "RFC 919 (Broadcast)"},
	{"192.88.99.1", false, "RFC 7526 (6to4 Relay Anycast)"},
	{"192.31.196.1", false, "RFC 7535 (AS112-v4)"},
	{"192.52.193.1", false, "RFC 7450 (AMT)"},
	{"192.0.0.170", false, "RFC 8880 (NAT64 Discovery)"},
	{"192.0.0.9", false, "RFC 7725 (PCP Anycast)"},

	// IPv6 Global Unicast (Valid)
	{"2600::", true, "Global Unicast"},
	{"2001:4860:4860::8888", true, "Google DNS"},
	{"3fff::1", true, "Public Space"},

	// IPv6 Bogons
	{"::1", false, "RFC 4291 (Loopback)"},
	{"::", false, "RFC 4291 (Unspecified)"},
	{"fe80::1", false, "RFC 4291 (Link-Local)"},
	{"fc00::1", false, "RFC 4193 (ULA)"},
	{"fd00::1", false, "RFC 4193 (ULA)"},
	{"2001::1", false, "RFC 2928 (IETF Protocol Assignments / Teredo)"},
	{"2001:1:2::3", false, "RFC 2928 (IETF Reserved Space)"},
	{"2001:10::1", false, "RFC 4843 (ORCHID)"},
	{"2001:2::1", false, "RFC 5180 (Benchmarks)"},
	{"2001:db8::1", false, "RFC 3849 (Documentation)"},
	{"2002::1", false, "RFC 3056 (6to4)"},
	{"100::1", false, "RFC 6666 (Discard)"},
	{"64:ff9b::1", false, "RFC 6052 (NAT64)"},
	{"64:ff9b:1::1", false, "RFC 8215 (Local-Use NAT64)"},
	{"3ffe::1", false, "RFC 3701 (6bone)"},
	{"ff02::1", false, "RFC 4291 (Multicast)"},
	{"2620:4f:8000::1", false, "RFC 7534 (AS112-v6)"},
	{"2001:30::1", false, "RFC 9385 (Drone Remote ID)"},
	{"2001:3::1", false, "RFC 7450 (AMT IPv6)"},
	{"4000::1", false, "RFC 4291 (Outside 2000::/3)"},

	// Edge Cases
	{"::ffff:1.2.3.4", true, "IPv4-mapped IPv6 (Public)"},
	{"::ffff:10.0.0.1", false, "IPv4-mapped IPv6 (Private)"},
}

func TestValidASN(t *testing.T) {
	t.Parallel()
	var tests = []struct {
		name string
		asn  uint32
		want bool
		rfc  string
	}{
		{"zero", 0, false, "RFC 6483"},
		{"one", 1, true, "Valid Public"},
		{"rfc6793", 23456, false, "RFC 6793 (AS_TRANS)"},
		{"rfc5398a", 64496, false, "RFC 5398 (Documentation)"},
		{"rfc5398b", 64511, false, "RFC 5398 (Documentation)"},
		{"rfc1930", 64512, false, "RFC 1930 (Private)"},
		{"rfc6996a", 65534, false, "RFC 6996 (Private)"},
		{"rfc7300a", 65535, false, "RFC 7300 (Reserved)"},
		{"rfc4893", 65551, false, "RFC 4893 (Reserved)"},
		{"rfc5398c", 131071, false, "RFC 5398 (Documentation)"},
		{"valid-4byte", 4199999999, true, "Valid 4-byte ASN"},
		{"rfc6996b", 4200000000, false, "RFC 6996 (Private)"},
		{"rfc7300b", 4294967295, false, "RFC 7300 (Reserved)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := bogons.ValidPublicASN(tt.asn)
			if got != tt.want {
				t.Errorf("ValidPublicASN(%d) [%s] = %v, want %v", tt.asn, tt.rfc, got, tt.want)
			}
		})
	}
}

func TestValidPublicIP(t *testing.T) {
	t.Parallel()
	for _, tt := range ipTests {
		t.Run(tt.ip, func(t *testing.T) {
			t.Parallel()
			got := bogons.ValidPublicIP(tt.ip)
			if got != tt.want {
				t.Errorf("ValidPublicIP(%q) [%s] = %v, want %v", tt.ip, tt.rfc, got, tt.want)
			}
		})
	}

	// Malformed inputs
	malformed := []string{"", "ghost", "1.1.1.1.1", ":::", "2001:db8::z"}
	for _, s := range malformed {
		t.Run("malformed_"+s, func(t *testing.T) {
			t.Parallel()
			if bogons.ValidPublicIP(s) {
				t.Errorf("ValidPublicIP(%q) should be false for malformed input", s)
			}
		})
	}
}

func TestValidPublicAddr(t *testing.T) {
	t.Parallel()
	for _, tt := range ipTests {
		t.Run(tt.ip, func(t *testing.T) {
			t.Parallel()
			addr, err := netip.ParseAddr(tt.ip)
			if err != nil {
				// ParseAddr handles mapped IPv4 differently than ParseIP/ParsePrefix
				// but for our test cases they should mostly work.
				// If it fails to parse, it shouldn't be a "want true" case.
				if tt.want {
					t.Fatalf("Failed to parse valid public IP %q: %v", tt.ip, err)
				}
				return
			}
			got := bogons.ValidPublicAddr(addr)
			if got != tt.want {
				t.Errorf("ValidPublicAddr(%q) [%s] = %v, want %v", tt.ip, tt.rfc, got, tt.want)
			}
		})
	}
}

func TestValidPublicPrefix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		prefix string
		want   bool
		rfc    string
	}{
		{"1.0.0.0/8", true, "RFC 791 (Valid IPv4)"},
		{"1.0.0.0/24", true, "RFC 791 (Valid IPv4)"},
		{"1.0.0.0/7", false, "Too short for IPv4"},
		{"1.0.0.0/25", false, "Too specific for IPv4"},
		{"10.0.0.0/8", false, "RFC 1918 (Private)"},
		{"1.0.0.1/24", false, "Host bits set (not normalized)"},

		{"2600::/16", true, "Global Unicast IPv6 (Min Length)"},
		{"2600::/32", true, "Global Unicast IPv6"},
		{"2600::/48", true, "Global Unicast IPv6 (Max Length)"},
		{"2600::/15", false, "Too short for IPv6"},
		{"2600::/49", false, "Too specific for IPv6"},
		{"2001:db8::/32", false, "RFC 3849 (Documentation)"},
		{"2600::1/32", false, "Host bits set (not normalized)"},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			t.Parallel()
			prefix, err := netip.ParsePrefix(tt.prefix)
			if err != nil {
				if tt.want {
					t.Fatalf("Failed to parse valid prefix %q: %v", tt.prefix, err)
				}
				return
			}
			got := bogons.ValidPublicPrefix(prefix)
			if got != tt.want {
				t.Errorf("ValidPublicPrefix(%q) [%s] = %v, want %v", tt.prefix, tt.rfc, got, tt.want)
			}
		})
	}
}

func TestLegacyShims(t *testing.T) {
	t.Parallel()
	for _, tt := range ipTests {
		t.Run(tt.ip, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				if tt.want {
					t.Fatalf("Failed to parse valid IP %q for legacy test", tt.ip)
				}
				return
			}

			// Test IsPublicIP
			if got := bogons.IsPublicIP(ip); got != tt.want {
				t.Errorf("IsPublicIP(%q) [%s] = %v, want %v", tt.ip, tt.rfc, got, tt.want)
			}

			// Test specific v4/v6 shims
			if ip.To4() != nil {
				if got := bogons.IsPublicIPv4(ip); got != tt.want {
					t.Errorf("IsPublicIPv4(%q) [%s] = %v, want %v", tt.ip, tt.rfc, got, tt.want)
				}
				// IPv4 should return false in IPv6 shim
				if got := bogons.IsPublicIPv6(ip); got {
					t.Errorf("IsPublicIPv6(%q) should be false for IPv4 address", tt.ip)
				}
			} else {
				if got := bogons.IsPublicIPv6(ip); got != tt.want {
					t.Errorf("IsPublicIPv6(%q) [%s] = %v, want %v", tt.ip, tt.rfc, got, tt.want)
				}
				// IPv6 should return false in IPv4 shim
				if got := bogons.IsPublicIPv4(ip); got {
					t.Errorf("IsPublicIPv4(%q) should be false for IPv6 address", tt.ip)
				}
			}
		})
	}
}

func TestCoverageEdgeCases(t *testing.T) {
	t.Parallel()

	// Zero netip.Addr (ValidPublicAddr)
	var zeroAddr netip.Addr
	if bogons.ValidPublicAddr(zeroAddr) {
		t.Error("ValidPublicAddr(zero) should be false")
	}

	// Invalid net.IP slice length (Legacy shims)
	invalidIP := net.IP{1, 2, 3} // Not 4 or 16 bytes
	if bogons.IsPublicIP(invalidIP) {
		t.Error("IsPublicIP(invalid) should be false")
	}
	if bogons.IsPublicIPv4(invalidIP) {
		t.Error("IsPublicIPv4(invalid) should be false")
	}
	if bogons.IsPublicIPv6(invalidIP) {
		t.Error("IsPublicIPv6(invalid) should be false")
	}
}

func TestCheckFunctions(t *testing.T) {
	t.Parallel()

	// CheckIP valid
	valid, reason := bogons.CheckIP("8.8.8.8")
	if !valid || reason != "" {
		t.Errorf("CheckIP(8.8.8.8) = (%v, %q), want (true, \"\")", valid, reason)
	}

	// CheckIP invalid syntax
	valid, reason = bogons.CheckIP("not-an-ip")
	if valid || reason != "Invalid IP address syntax" {
		t.Errorf("CheckIP(not-an-ip) = (%v, %q)", valid, reason)
	}

	// CheckIP private RFC 1918
	valid, reason = bogons.CheckIP("192.168.1.1")
	if valid || reason != "RFC 1918 (Private-Use)" {
		t.Errorf("CheckIP(192.168.1.1) = (%v, %q), want false with RFC 1918", valid, reason)
	}

	// CheckIP CGNAT RFC 6598
	valid, reason = bogons.CheckIP("100.64.0.1")
	if valid || reason != "RFC 6598 (Shared Address Space / CGNAT)" {
		t.Errorf("CheckIP(100.64.0.1) = (%v, %q), want false with RFC 6598", valid, reason)
	}

	// CheckIP Loopback RFC 1122
	valid, reason = bogons.CheckIP("127.0.0.1")
	if valid || reason != "RFC 1122 (Loopback)" {
		t.Errorf("CheckIP(127.0.0.1) = (%v, %q)", valid, reason)
	}

	// CheckIP Documentation RFC 5737
	valid, reason = bogons.CheckIP("192.0.2.1")
	if valid || reason != "RFC 5737 (Documentation TEST-NET-1)" {
		t.Errorf("CheckIP(192.0.2.1) = (%v, %q)", valid, reason)
	}

	// CheckIP Deprecated 6to4 RFC 7526
	valid, reason = bogons.CheckIP("192.88.99.1")
	if valid || reason != "RFC 7526 (6to4 Relay Anycast - Deprecated)" {
		t.Errorf("CheckIP(192.88.99.1) = (%v, %q)", valid, reason)
	}

	// CheckIP IPv6 ULA RFC 4193
	valid, reason = bogons.CheckIP("fc00::1")
	if valid || reason != "RFC 4193 (Unique Local Address / ULA)" {
		t.Errorf("CheckIP(fc00::1) = (%v, %q)", valid, reason)
	}

	// CheckIP IPv6 Documentation RFC 3849
	valid, reason = bogons.CheckIP("2001:db8::1")
	if valid || reason != "RFC 3849 (Documentation)" {
		t.Errorf("CheckIP(2001:db8::1) = (%v, %q)", valid, reason)
	}

	// CheckIP IPv6 Outside 2000::/3
	valid, reason = bogons.CheckIP("4000::1")
	if valid || reason != "RFC 4291 (IANA Unallocated / Outside 2000::/3 Global Unicast)" {
		t.Errorf("CheckIP(4000::1) = (%v, %q)", valid, reason)
	}

	// CheckASN
	valid, reason = bogons.CheckASN(15169)
	if !valid || reason != "" {
		t.Errorf("CheckASN(15169) = (%v, %q), want (true, \"\")", valid, reason)
	}

	valid, reason = bogons.CheckASN(64512)
	if valid || reason != "RFC 1930 / RFC 6996 (Private-Use 16-bit)" {
		t.Errorf("CheckASN(64512) = (%v, %q)", valid, reason)
	}

	valid, reason = bogons.CheckASN(0)
	if valid || reason != "RFC 6483 / RFC 7607 (Reserved ASN 0)" {
		t.Errorf("CheckASN(0) = (%v, %q)", valid, reason)
	}

	// CheckASNString: decimal, AS prefix, asdot, bogon reason, malformed
	valid, reason = bogons.CheckASNString("15169")
	if !valid || reason != "" {
		t.Errorf("CheckASNString(15169) = (%v, %q)", valid, reason)
	}

	valid, reason = bogons.CheckASNString("AS15169")
	if !valid || reason != "" {
		t.Errorf("CheckASNString(AS15169) = (%v, %q)", valid, reason)
	}

	valid, reason = bogons.CheckASNString("as64512")
	if valid || reason != "RFC 1930 / RFC 6996 (Private-Use 16-bit)" {
		t.Errorf("CheckASNString(as64512) = (%v, %q)", valid, reason)
	}

	// asdot notation: 1.0 = 65536 (RFC 5398 32-bit documentation)
	valid, reason = bogons.CheckASNString("1.0")
	if valid || reason != "RFC 5398 (Documentation 32-bit)" {
		t.Errorf("CheckASNString(1.0) = (%v, %q)", valid, reason)
	}

	valid, reason = bogons.CheckASNString("not-an-asn")
	if valid || reason != "Invalid ASN syntax" {
		t.Errorf("CheckASNString(not-an-asn) = (%v, %q)", valid, reason)
	}

	if !bogons.ValidPublicASNString("AS15169") {
		t.Errorf("ValidPublicASNString(AS15169) should be true")
	}

	if bogons.ValidPublicASNString("AS64512") {
		t.Errorf("ValidPublicASNString(AS64512) should be false")
	}
}

func TestCheckPrefixNoBitBoundaryRestriction(t *testing.T) {
	t.Parallel()

	// A /25 public subnet: should be valid in CheckPrefix (ignoring /24 boundary)
	p25 := netip.MustParsePrefix("8.8.8.0/25")
	valid, reason := bogons.CheckPrefix(p25)
	if !valid || reason != "" {
		t.Errorf("CheckPrefix(8.8.8.0/25) = (%v, %q), want (true, \"\")", valid, reason)
	}

	// But ValidPublicPrefix rejects /25 due to BGP boundary rules
	if bogons.ValidPublicPrefix(p25) {
		t.Error("ValidPublicPrefix(8.8.8.0/25) should be false due to BGP /24 rule")
	}

	// A /32 public subnet: should be valid in CheckPrefix
	p32 := netip.MustParsePrefix("1.1.1.1/32")
	valid, reason = bogons.CheckPrefix(p32)
	if !valid || reason != "" {
		t.Errorf("CheckPrefix(1.1.1.1/32) = (%v, %q), want (true, \"\")", valid, reason)
	}

	// A /28 private subnet: sits in RFC 1918 bogon subnet
	privPfx := netip.MustParsePrefix("10.1.2.0/28")
	valid, reason = bogons.CheckPrefix(privPfx)
	if valid || reason != "RFC 1918 (Private-Use)" {
		t.Errorf("CheckPrefix(10.1.2.0/28) = (%v, %q), want false with RFC 1918", valid, reason)
	}
}

