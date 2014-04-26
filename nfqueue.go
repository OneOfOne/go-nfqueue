package nfqueue

/*
#cgo LDFLAGS: -lnetfilter_queue
#cgo CFLAGS: -Wall
#include "nfqueue.h"
*/
import "C"

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type nfQueue struct {
	DefaultVerdict Verdict
	Timeout        time.Duration
	qid            uint16
	h              *C.struct_nfq_handle
	qh             *C.struct_q_handle
	fd             int
	lk             sync.Mutex

	pktch chan *Packet
}

func NewNFQueue(qid uint16) (nfq *nfQueue) {
	if u, _ := user.Current(); u.Uid != "0" {
		panic("Must be ran by root.")
	}
	nfq = &nfQueue{DefaultVerdict: ACCEPT, Timeout: time.Microsecond * 5, qid: qid}
	return nfq
}

/*
This returns a channel that will recieve packets,
the user then must call pkt.Accept() or pkt.Drop()
*/
func (this *nfQueue) Proccess() <-chan *Packet {
	if this.h != nil {
		return this.pktch
	}
	this.init()

	go func() {
		var (
			buf  = make([]byte, 256) //
			bufp = (*C.char)(unsafe.Pointer(&buf[0]))
		)

		for {
			n, err := syscall.Read(this.fd, buf)
			switch {
			case n > 0 && err == nil:
				C.nfq_handle_packet(this.h, bufp, C.int(n))
			default:
				fmt.Fprintf(os.Stderr, "nfqueue read error %+v\n", err)
				break
			}
		}
	}()

	return this.pktch
}

func (this *nfQueue) init() {
	var err error
	if this.h, err = C.nfq_open(); err != nil || this.h == nil {
		panic(err)
	}

	//if this.qh, err = C.nfq_create_queue(this.h, qid, C.get_cb(), unsafe.Pointer(nfq)); err != nil || this.qh == nil {

	this.pktch = make(chan *Packet, 1)

	if C.nfq_unbind_pf(this.h, C.AF_INET) < 0 {
		this.Destroy()
		panic("nfq_unbind_pf(AF_INET) failed, are you running root?.")
	}
	if C.nfq_unbind_pf(this.h, C.AF_INET6) < 0 {
		this.Destroy()
		panic("nfq_unbind_pf(AF_INET6) failed.")
	}

	if C.nfq_bind_pf(this.h, C.AF_INET) < 0 {
		this.Destroy()
		panic("nfq_bind_pf(AF_INET) failed.")
	}

	if C.nfq_bind_pf(this.h, C.AF_INET6) < 0 {
		this.Destroy()
		panic("nfq_bind_pf(AF_INET6) failed.")
	}

	if this.qh, err = C.create_queue(this.h, C.uint16_t(this.qid), unsafe.Pointer(this)); err != nil || this.qh == nil {
		C.nfq_close(this.h)
		panic(err)
	}

	this.fd = int(C.nfq_fd(this.h))

	if C.nfq_set_mode(this.qh, C.NFQNL_COPY_PACKET, 0xffff) < 0 {
		this.Destroy()
		panic("nfq_set_mode(NFQNL_COPY_PACKET) failed.")
	}
	if C.nfq_set_queue_maxlen(this.qh, 1024*8) < 0 {
		this.Destroy()
		panic("nfq_set_queue_maxlen(1024 * 8) failed.")
	}
}

func (this *nfQueue) Destroy() {
	this.lk.Lock()
	defer this.lk.Unlock()

	if this.fd != 0 && this.Valid() {
		syscall.Close(this.fd)
	}
	if this.qh != nil {
		C.nfq_destroy_queue(this.qh)
		this.qh = nil
	}
	if this.h != nil {
		C.nfq_close(this.h)
		this.h = nil
	}

	if this.pktch != nil {
		close(this.pktch)
	}
}

func (this *nfQueue) Valid() bool {
	return this.h != nil && this.qh != nil
}

//export go_nfq_callback
func go_nfq_callback(id uint32, hwproto uint16, hook uint8, mark *uint32,
	version, protocol, tos, ttl uint8, saddr, daddr unsafe.Pointer,
	sport, dport, checksum uint16, payload, nfqptr unsafe.Pointer) (v uint32) {

	var (
		nfq   = (*nfQueue)(nfqptr)
		ipver = IPVersion(version)
		ipsz  = C.int(ipver.Size())
	)

	verdict := make(chan uint32, 1)
	pkt := Packet{
		Id:         id,
		HWProtocol: hwproto,
		Hook:       hook,
		Mark:       *mark,
		IPHeader: &IPHeader{
			Version:  ipver,
			Protocol: IPProtocol(protocol),
			Tos:      tos,
			TTL:      ttl,
			Src:      net.IP(C.GoBytes(saddr, ipsz)),
			Dst:      net.IP(C.GoBytes(daddr, ipsz)),
		},

		TCPUDPHeader: &TCPUDPHeader{
			SrcPort:  sport,
			DstPort:  dport,
			Checksum: checksum,
		},

		verdict: verdict,
	}
	nfq.pktch <- &pkt

	select {
	case v = <-pkt.verdict:
		*mark = pkt.Mark
	case <-time.After(nfq.Timeout):
		v = uint32(nfq.DefaultVerdict)
	}
	close(pkt.verdict)
	return v
}
