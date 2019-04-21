package main

import (
	"net"
	"strconv"
	"fmt"
	"sntp"
)

func main() {
	addr, err := net.ResolveUDPAddr("udp", ":"+strconv.Itoa(10000))
	if err != nil {
		fmt.Println("resolve addr err")
		return
	}
	c, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println("listen err")
		return
	}

	for {
		data := make([]byte, 512)
		readLength, remoteAddr, err := c.ReadFromUDP(data[0:])
		if err != nil { // EOF, or worse
			continue
		}
		if readLength > 0 {
			res, err := sntp.Serve(data[0:readLength])
			if err != nil {
				fmt.Println("serve err: " + err.Error())
				continue
			}
			_, er := c.WriteTo(res, remoteAddr)
			if er != nil {
				fmt.Println(er)
				continue
			}
		}
	}
}
