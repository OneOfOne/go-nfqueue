package nfqueue

import (
	"fmt"
	"net"
	"syscall"
)

type IPVersion uint8
type IPProtocol uint8
type Verdict uint8

const (
	IPv4 = IPVersion(4)
	IPv6 = IPVersion(6)

	//convience really
	RAW    = IPProtocol(syscall.IPPROTO_RAW)
	TCP    = IPProtocol(syscall.IPPROTO_TCP)
	UDP    = IPProtocol(syscall.IPPROTO_UDP)
	ICMP   = IPProtocol(syscall.IPPROTO_ICMP)
	ICMPv6 = IPProtocol(syscall.IPPROTO_ICMPV6)
)
const (
	DROP Verdict = iota
	ACCEPT
	STOLEN
	QUEUE
	REPEAT
	STOP
)

func (this IPVersion) String() string {
	switch this {
	case IPv4:
		return "IPv4"
	case IPv6:
		return "IPv6"
	default:
		return fmt.Sprintf("<unknown ip version, %d>", uint8(this))
	}
}

func (this IPProtocol) String() string {
	switch this {
	case RAW:
		return "RAW"
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	case ICMP:
		return "ICMP"
	case ICMPv6:
		return "ICMPv6"
	default:
		return fmt.Sprintf("<unknown protocol, %d>", uint8(this))
	}
}

func (this Verdict) String() string {
	switch this {
	case DROP:
		return "DROP"
	case ACCEPT:
		return "ACCEPT"
	default:
		return fmt.Sprintf("<unsupported verdict, %d>", this)
	}
}

type IPHeader struct {
	Version IPVersion

	Tos, TTL   uint8
	Protocol   IPProtocol
	Id, Length uint16
	Src, Dst   net.IP
}

type TCPUDPHeader struct {
	SrcPort, DstPort uint16
	Checksum         uint16
}

// TODO handle other protocols

type Packet struct {
	Id         uint32
	HWProtocol uint16
	Hook       uint8

	IP *IPHeader
}
