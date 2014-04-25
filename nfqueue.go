package nfqueue

/*
#cgo LDFLAGS: -lnetfilter_queue
//#cgo CFLAGS: -Wno-implicit-function-declaration
#include "nfqueue.h"
*/
import "C"

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"unsafe"
)

type nfQueue struct {
	Handled uint64
	h       *C.struct_nfq_handle
	qh      *C.struct_q_handle
	fd      uintptr
	once    sync.Once
}

func NewNFQueue(qid uint16) (nfq *nfQueue) {
	nfq = &nfQueue{}
	var err error
	if nfq.h, err = C.nfq_open(); err != nil || nfq.h == nil {
		panic(err)
	}

	//if nfq.qh, err = C.nfq_create_queue(nfq.h, qid, C.get_cb(), unsafe.Pointer(nfq)); err != nil || nfq.qh == nil {
	if nfq.qh, err = C.create_queue(nfq.h, C.uint16_t(qid), unsafe.Pointer(nfq)); err != nil || nfq.qh == nil {
		C.nfq_close(nfq.h)
		panic(err)
	}
	runtime.SetFinalizer(nfq, func(nfq *nfQueue) {
		nfq.Destroy()
	})

	C.nfq_set_mode(nfq.qh, C.NFQNL_COPY_PACKET, 0xffff)
	C.nfq_set_queue_maxlen(nfq.qh, 10240)
	C.nfq_unbind_pf(nfq.h, C.AF_INET)
	C.nfq_unbind_pf(nfq.h, C.AF_INET6)
	C.nfq_bind_pf(nfq.h, C.AF_INET)
	C.nfq_bind_pf(nfq.h, C.AF_INET6)
	nfq.fd = uintptr(C.nfq_fd(nfq.h))

	go func() {
		runtime.LockOSThread() // I don't like surprises, so might as well just lock this goroutine in thread.
		var (
			buf  = make([]byte, 256) //
			bufp = (*C.char)(unsafe.Pointer(&buf[0]))
			f    = os.NewFile(nfq.fd, "<nfq>")
		)
		fmt.Printf("%+v %#v\n", C.nfq_fd(nfq.h), f.Fd())
		//conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		for {
			n, err := f.Read(buf)
			switch {
			case n > 0 && err == nil:
				go C.nfq_handle_packet(nfq.h, bufp, C.int(n))
			// case err.(net.Error).Timeout():
			// 	runtime.Gosched()
			// 	time.Sleep(100 * time.Millisecond)
			// case err.(syscall.Errno) == syscall.ENOBUFS:
			// 	fmt.Fprintln(os.Stderr, "recvfrom", err, uint64(err.(syscall.Errno)))
			// 	continue
			default:
				fmt.Fprintln(os.Stderr, "recvfrom", err)
				//nfq.Close()
				break
			}
			//conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		}
	}()
	return nfq
}

func (this *nfQueue) Destroy() {
	this.once.Do(func() {
		if this.qh != nil {
			C.nfq_destroy_queue(this.qh)
			this.qh = nil
		}
		if this.h != nil {
			C.nfq_close(this.h)
			this.h = nil
		}
	})
}

func (this *nfQueue) Valid() bool {
	return this.h != nil && this.qh != nil
}

//export go_nfq_callback
func go_nfq_callback(version, protocol uint8, saddr, daddr unsafe.Pointer, sport, dport uint16, extra, nfq_handle unsafe.Pointer) int {

	return int(ACCEPT)
}
