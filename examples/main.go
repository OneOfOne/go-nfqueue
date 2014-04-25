package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"

	"github.com/OneOfOne/go-nfqueue"
)

func print_packets(qid uint16, pkt *nfqueue.Packet) {
	fmt.Println(pkt)
	pkt.Accept()
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU()) //if it's less than 2, the program will never exit, it blocks on recv
	var (
		q = nfqueue.NewNFQueue(0)
	)
	defer q.Destroy()
	fmt.Println("The queue is active, add an iptables rule to use it, for example: ")
	fmt.Println("\tiptables -I INPUT 1 -m conntrack --ctstate NEW -j NFQUEUE --queue-num", 0)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	packets := q.Proccess()

LOOP:
	for {
		select {
		case pkt := <-packets:
			fmt.Println(pkt)
			pkt.Accept()
		case <-sig:
			break LOOP
		}

	}
	fmt.Println("Exiting, remember to remove the iptables rule :")
	fmt.Println("\tiptables -D INPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num", 0)
}
