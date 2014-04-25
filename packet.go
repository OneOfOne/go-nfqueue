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
	IGMP   = IPProtocol(syscall.IPPROTO_IGMP)
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
	}
	return fmt.Sprintf("<unknown ip version, %d>", uint8(this))
}

// Returns the byte size of the ip, IPv4 = 4 bytes, IPv6 = 16
func (this IPVersion) Size() int {
	switch this {
	case IPv4:
		return 4
	case IPv6:
		return 16
	}
	return 0
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
	case IGMP:
		return "IGMP"
	}
	return fmt.Sprintf("<unknown protocol, %d>", uint8(this))
}

func (this Verdict) String() string {
	switch this {
	case DROP:
		return "DROP"
	case ACCEPT:
		return "ACCEPT"
	}
	return fmt.Sprintf("<unsupported verdict, %d>", uint8(this))
}

type IPHeader struct {
	Version IPVersion

	Tos, TTL uint8
	Protocol IPProtocol
	Src, Dst net.IP
}

type TCPUDPHeader struct {
	SrcPort, DstPort uint16
	Checksum         uint16 //not implemented
}

// TODO handle other protocols

type Packet struct {
	Id         uint32
	HWProtocol uint16
	Hook       uint8
	Mark       uint32
	*IPHeader
	*TCPUDPHeader

	nfq *nfQueue
}

func (this *Packet) String() string {
	return fmt.Sprintf("<Packet Id: %d, Type: %s, Src: %s:%d, Dst: %s:%d>, Mark: 0x%X, Checksum: 0x%X, TOS: 0x%X, TTL: %d",
		this.Id, this.Protocol, this.Src, this.SrcPort, this.Dst, this.DstPort, this.Mark, this.Checksum, this.Tos, this.TTL)
}

func (this *Packet) Accept() {
	if this.nfq != nil {
		this.nfq.setVerdict(this.Id, this.Mark, ACCEPT)
		this.nfq = nil
	} else {
		panic("Called Accept() on an invalid nfQueue.")
	}
}

func (this *Packet) Drop() {
	if this.nfq != nil {
		this.nfq.setVerdict(this.Id, this.Mark, DROP)
		this.nfq = nil
	} else {
		panic("Called Accept() on an invalid nfQueue.")
	}
}
