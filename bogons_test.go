package bogons_test

import (
	"testing"

	"github.com/mellowdrifter/bogons"
)

func TestValidASN(t *testing.T) {
	t.Parallel()
	var tests = []struct {
		name string
		asn  uint32
		want bool
	}{
		{"zero", 0, false},
		{"one", 1, true},
		{"rfc6793", 23456, false},
		{"rfc5398", 64496, false},
		{"rfc5398", 64511, false},
		{"rfc1930", 64512, false},
		{"rfc6996", 65534, false},
		{"rfc7300", 65535, false},
		{"rfc4893", 65551, false},
		{"rfc5398", 131071, false},
		{"valid", 4199999999, true},
		{"rfc6996", 4200000000, false},
		{"rfc7300", 4294967295, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bogons.ValidPublicASN(tt.asn)
			if got != tt.want {
				t.Errorf("Expected %v, got %v, with value %d", got, tt.want, tt.asn)
			}
		})
	}
}

func TestValidIP(t *testing.T) {
	t.Parallel()
	var tests = []struct {
		ip   string
		want bool
	}{
		{"0.0.0.1", false},
		{"1.1.1.1", true},
		{"10.1.1.1", false},
		{"11.1.1.1", true},
		{"11.1.1.1.1", false},
		{"172.16.1.1", false},
		{"100.64.0.1", false},
		{"100.127.0.0", false},
		{"169.254.10.1", false},
		{"192.0.0.1", false},
		{"192.0.1.1", true},
		{"192.0.2.1", false},
		{"192.168.1.1", false},
		{"193.168.1.1", true},
		{"198.18.100.2", false},
		{"198.51.100.2", false},
		{"203.0.113.2", false},
		{"224.168.1.1", false},
		{"11.1.1.1.1", false},
		{"2001:1:2::3", false},
		{"2001:db8:1:2::3", false},
		{"2002:b8:1:2::3", false},
		{"2600::", true},
		{"3ffe::", false},
		{"3fff::", true},
		{"3fff:::", false},
		{"4600::", false},
		{"", false},
		{"👻", false},
	}
	for _, tt := range tests {
		got := bogons.ValidPublicIP(tt.ip)
		if got != tt.want {
			t.Errorf("Expected %v, got %v, with value %s", tt.want, got, tt.ip)
		}
	}
}
