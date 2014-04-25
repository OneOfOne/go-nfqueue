Go-NFQueue
==========
Go Wrapper For Creating IPTables' NFQueue clients in Go

Usage
------
Check the `examples/main.go` file

	cd $GOPATH/github.com/OneOfOne/go-nfqueue/examples
	go build -race && sudo ./examples

Open another terminal :

	sudo iptables -I INPUT 1 -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0
	curl --head localhost
	ping localhost
	sudo iptables -D INPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 0

Then you can `ctrl+c` the program to exit.

**Note*** that you must run it as root.

Notes
-----
You must run the program as root 
License
-------
go-nfqueue is under the Apache v2 license, check the included license file.
Copyright © [Ahmed W.](http://www.limitlessfx.com/)
See the included `LICENSE` file.

> Copyright (c) 2014 Ahmed W.