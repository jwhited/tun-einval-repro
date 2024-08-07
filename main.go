package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	flagTunName = flag.String("tun-name", "tun0", "name of TUN device")
	flagTunAddr = flag.String("tun-addr", "172.16.0.1/24", "TUN device L3 addr")
)

// setupTUN creates a TUN interface, writable via file. It can be cleaned up by
// calling the returned closure cleanup.
func setupTUN() (file *os.File, cleanup func()) {
	nfd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		log.Panic(err)
	}

	ifr, err := unix.NewIfreq(*flagTunName)
	if err != nil {
		unix.Close(nfd)
		log.Panic(err)
	}

	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	err = unix.IoctlIfreq(nfd, unix.TUNSETIFF, ifr)
	if err != nil {
		unix.Close(nfd)
		log.Panic(err)
	}

	err = unix.SetNonblock(nfd, true)
	if err != nil {
		unix.Close(nfd)
		log.Panic(err)
	}

	err = unix.IoctlSetInt(nfd, unix.TUNSETOFFLOAD, unix.TUN_F_CSUM|unix.TUN_F_USO4|unix.TUN_F_USO6|unix.TUN_F_TSO4|unix.TUN_F_TSO6)
	if err != nil {
		unix.Close(nfd)
		log.Panic(err)
	}

	file = os.NewFile(uintptr(nfd), "/dev/net/tun")

	cmd := exec.Command("/usr/sbin/ip", "addr", "add", *flagTunAddr, "dev", *flagTunName)
	err = cmd.Run()
	if err != nil {
		file.Close()
		unix.Close(nfd)
		log.Panic(err)
	}

	cmd = exec.Command("/usr/sbin/ip", "link", "set", *flagTunName, "up")
	err = cmd.Run()
	if err != nil {
		file.Close()
		unix.Close(nfd)
		log.Panic(err)
	}

	cleanup = func() {
		file.Close()
		unix.Close(nfd)
	}

	return file, cleanup
}

const virtioNetHdrLen = int(unsafe.Sizeof(virtioNetHdr{}))

type virtioNetHdr struct {
	flags      uint8
	gsoType    uint8
	hdrLen     uint16
	gsoSize    uint16
	csumStart  uint16
	csumOffset uint16
}

func (v *virtioNetHdr) encode(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return io.ErrShortBuffer
	}
	copy(b[:virtioNetHdrLen], unsafe.Slice((*byte)(unsafe.Pointer(v)), virtioNetHdrLen))
	return nil
}

// checksum returns the RFC 1071 checksum of b
func checksum(b []byte, initial uint16) uint16 {
	var ac uint32
	ac += uint32(initial)
	i := 0
	n := len(b)
	for n >= 2 {
		ac += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		n -= 2
		i += 2
	}
	if n == 1 {
		ac += uint32(b[i]) << 8
	}
	for (ac >> 16) > 0 {
		ac = (ac >> 16) + (ac & 0xffff)
	}
	return uint16(ac)
}

// tcpPsuedoChecksum returns the RFC 1071 pseudo header checksum of a packet
// with src, dst, and dataLen.
func tcpPsuedoChecksum(src, dst []byte, dataLen int) uint16 {
	pseudo := make([]byte, 12)
	copy(pseudo, src)
	copy(pseudo[4:], dst)
	pseudo[9] = 6 // protocol TCP
	binary.BigEndian.PutUint16(pseudo[10:], uint16(dataLen))
	return checksum(pseudo, 0)
}

func main() {
	flag.Parse()
	f, closeTUN := setupTUN()
	defer closeTUN()

	src := netip.MustParseAddr("192.0.2.1")
	srcPort := uint16(7)
	dst := netip.MustParseAddr("192.0.2.2")
	dstPort := uint16(77)

	pkt := make([]byte, virtioNetHdrLen+20+20+1240+1240) // virtio + ipv4H + tcpH + gso 1240 + gso 1240 = 2530 bytes
	hdr := virtioNetHdr{
		flags:      1,    // needs_csum
		gsoType:    1,    // gso tcpv4
		hdrLen:     40,   // len of ip + tcp headers
		gsoSize:    1240, // segment payload len
		csumStart:  20,   // start of tcp header
		csumOffset: 16,   // csum field offset in tcp header
	}
	err := hdr.encode(pkt)
	if err != nil {
		log.Panic(err)
	}

	ipH := pkt[10:]
	ipH[0] = 0x45                                                // version 4, header length 20 bytes
	binary.BigEndian.PutUint16(ipH[2:], uint16(len(pkt[10:])))   // total len
	ipH[8] = 64                                                  // TTL
	ipH[9] = 6                                                   // protocol TCP
	copy(ipH[12:16], src.AsSlice())                              // src
	copy(ipH[16:20], dst.AsSlice())                              // dst
	binary.BigEndian.PutUint16(ipH[10:], ^checksum(ipH[:20], 0)) // ipv4 checksum

	tcpH := ipH[20:]
	binary.BigEndian.PutUint16(tcpH, srcPort)       // src port
	binary.BigEndian.PutUint16(tcpH[2:], dstPort)   // dst port
	binary.BigEndian.PutUint32(tcpH[4:], uint32(1)) // seq
	tcpH[12] = 5 << 4                               // data offset
	pseudo := tcpPsuedoChecksum(src.AsSlice(), dst.AsSlice(), len(pkt)-virtioNetHdrLen-20)
	binary.BigEndian.PutUint16(tcpH[16:], pseudo) // tcp checksum (partial)

	_, err = f.Write(pkt)
	if err != nil {
		log.Printf("error writing packet to TUN: %v", err)
		os.Exit(1)
	}
	log.Println("successfully wrote packet")
}
