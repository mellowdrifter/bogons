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
		//{65534, false},
		//{65535, false},
		//{65551, false},
		//{131071, false},
		//{4199999999, true},
		//{4200000000, false},
		//{4294967295, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bogons.ValidASN(tt.asn)
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
		{"192.168.1.1", false},
		{"193.168.1.1", true},
		{"224.168.1.1", false},
		{"11.1.1.1.1", false},
		{"2600::", true},
		{"3fff::", true},
		{"3fff:::", false},
		{"4600::", false},
		{"", false},
		{"👻", false},
	}
	for _, tt := range tests {
		got := bogons.ValidIP(tt.ip)
		if got != tt.want {
			t.Errorf("Expected %v, got %v, with value %s", got, tt.want, tt.ip)
		}
	}
}
