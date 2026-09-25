//go:build linux

// Command init runs as PID 1 in a throwaway virtual machine that checks
// socktrail on another kernel or architecture; test/vm/run.sh builds it into
// the initramfs. It mounts the pseudo filesystems, brings up lo, runs the
// probes' root tests and a short capture of traffic it makes itself, prints
// one VM-RESULT line for run.sh, and powers off.
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type result struct {
	passed, failed, skipped int
	flows, dropped          int
	opensslEvents           int
	socktrailOK             bool
}

func main() {
	defer func() { _ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF) }()
	for _, m := range [][3]string{{"proc", "/proc", "proc"}, {"sysfs", "/sys", "sysfs"}, {"devtmpfs", "/dev", "devtmpfs"}, {"tmpfs", "/tmp", "tmpfs"}} {
		if err := syscall.Mount(m[0], m[1], m[2], 0, ""); err != nil {
			fmt.Println("mount", m[1], err)
		}
	}
	if err := linkUp("lo"); err != nil {
		fmt.Println("lo up:", err)
	}
	// Let ping sockets (SOCK_DGRAM ICMP) be created, as many distributions do.
	_ = os.WriteFile("/proc/sys/net/ipv4/ping_group_range", []byte("0 2147483647"), 0)
	version, _ := os.ReadFile("/proc/version")
	fmt.Printf("VM kernel (%s): %s", runtime.GOARCH, version)
	var r result
	for _, test := range []string{"/bin/probe.test", "/bin/sockstream.test", "/bin/capture.test", "/bin/conntrack.test"} {
		r.test(test)
	}
	r.capture()
	fmt.Printf("VM-RESULT tests-passed=%d tests-failed=%d tests-skipped=%d flows=%d capture-dropped=%d openssl-sni-events=%d socktrail-ok=%t\n",
		r.passed, r.failed, r.skipped, r.flows, r.dropped, r.opensslEvents, r.socktrailOK)
}

// test runs one test binary verbosely and counts its results; a binary that
// fails without a failing test, such as on a panic, counts as one failure.
func (r *result) test(path string) {
	cmd := exec.Command(path, "-test.v")
	out, err := cmd.StdoutPipe()
	if err != nil {
		r.failed++
		return
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		fmt.Println("start", path, err)
		r.failed++
		return
	}
	failed := 0
	lines := bufio.NewScanner(out)
	for lines.Scan() {
		line := lines.Text()
		fmt.Println(line)
		switch {
		case strings.HasPrefix(line, "--- PASS"):
			r.passed++
		case strings.HasPrefix(line, "--- FAIL"):
			failed++
		case strings.HasPrefix(line, "--- SKIP"):
			r.skipped++
		}
	}
	if err := cmd.Wait(); err != nil && failed == 0 {
		failed = 1
	}
	r.failed += failed
	fmt.Println("== ran", path, "failed", failed)
}

func linkUp(name string) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(fd) }()
	var ifr [40]byte
	copy(ifr[:16], name)
	//nolint:gosec // G103: ioctl requires the kernel network-interface ABI layout.
	*(*uint16)(unsafe.Pointer(&ifr[16])) = syscall.IFF_UP
	//nolint:gosec // G103: ioctl requires the kernel network-interface ABI layout.
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return errno
	}
	return nil
}

// capture runs a socktrail snapshot of lo while making traffic, and reads
// the flow rows, capture drops and OpenSSL events from its report.
func (r *result) capture() {
	cmd := exec.Command("/bin/socktrail", "--interface", "lo", "--duration", "12s", "--limit", "60")
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stdout
	if err := cmd.Start(); err != nil {
		fmt.Println("start socktrail:", err)
		return
	}
	lines := bufio.NewScanner(out)
	for lines.Scan() { // Every probe is up once the last status line is out.
		fmt.Println(lines.Text())
		if strings.HasPrefix(lines.Text(), "NAT mapping") {
			break
		}
	}
	traffic()
	for lines.Scan() {
		line := lines.Text()
		fmt.Println(line)
		for _, protocol := range []string{"TCP ", "UDP ", "ICMPv4 ", "ICMPv6 "} {
			if strings.HasPrefix(line, protocol) {
				r.flows++
			}
		}
		_, _ = fmt.Sscanf(line, "OpenSSL SNI events %d", &r.opensslEvents)
		if rest, ok := strings.CutPrefix(line, "capture status: AF_PACKET delivered="); ok {
			var delivered int
			_, _ = fmt.Sscanf(rest, "%d dropped=%d", &delivered, &r.dropped)
		}
	}
	err := cmd.Wait()
	r.socktrailOK = err == nil
	fmt.Println("== socktrail exit:", err)
}

func traffic() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	if ln, err := net.Listen("tcp", "127.0.0.1:18080"); err == nil {
		//nolint:gosec // G114: this short-lived VM smoke server listens on loopback only.
		go func() { _ = http.Serve(ln, handler) }()
	}
	if ln, err := tls.Listen("tcp", "127.0.0.1:18443", &tls.Config{Certificates: []tls.Certificate{selfSigned()}}); err == nil {
		//nolint:gosec // G114: this short-lived VM smoke server listens on loopback only.
		go func() { _ = http.Serve(ln, handler) }()
	}

	request, _ := http.NewRequest("GET", "http://127.0.0.1:18080/", nil)
	request.Host = "vm.example.test"
	report("http", doRequest(http.DefaultClient, request))
	//nolint:gosec // G402: the VM smoke test connects to its own self-signed local server.
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: "tls.vm.test", InsecureSkipVerify: true}}}
	request, _ = http.NewRequest("GET", "https://127.0.0.1:18443/", nil)
	report("https", doRequest(client, request))
	openssl()

	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18053})
	if err == nil {
		defer func() { _ = receiver.Close() }()
		sender, _ := net.Dial("udp", "127.0.0.1:18053")
		_, _ = sender.Write([]byte("datagram"))
		_ = sender.Close()
	}
	// The RFC 9001 sample client Initial, which names example.com.
	if text, err := os.ReadFile("/data/quic-initial.hex"); err == nil {
		initial, err := hex.DecodeString(strings.Join(strings.Fields(string(text)), ""))
		if err == nil {
			quic, _ := net.ListenUDP("udp", nil) // Unconnected, like quic-go.
			_, _ = quic.WriteToUDP(initial, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
			_ = quic.Close()
		}
	}
	// A raw socket echo request carries its identifier in the message.
	if raw, err := net.ListenPacket("ip4:icmp", "127.0.0.1"); err == nil {
		for seq := range byte(3) {
			_, _ = raw.WriteTo(echo(0x4242, seq), &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
		}
		_ = raw.Close()
	}
	// A ping socket gets its identifier from the kernel.
	if fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP); err == nil {
		to := &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}
		for seq := range byte(3) {
			report("ping socket", syscall.Sendto(fd, echo(0, seq), 0, to))
		}
		_ = syscall.Close(fd)
	} else {
		report("ping socket", err)
	}
}

// openssl makes a handshake with the distribution's openssl client, whose
// SNI the OpenSSL probe must report with the client's PID.
func openssl() {
	triplet := map[string]string{"amd64": "x86_64-linux-gnu", "arm64": "aarch64-linux-gnu"}[runtime.GOARCH]
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/openssl", "s_client", "-connect", "127.0.0.1:18443", "-servername", "openssl.vm.test", "-brief")
	cmd.Env = []string{"LD_LIBRARY_PATH=/lib/" + triplet + ":/usr/lib/" + triplet}
	out, err := cmd.CombinedOutput()
	fmt.Printf("openssl s_client: %v\n%s", err, out)
}

func doRequest(client *http.Client, request *http.Request) error {
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, response.Body)
	return response.Body.Close()
}

func report(what string, err error) {
	if err != nil {
		fmt.Println(what+":", err)
	}
}

// echo builds an ICMP echo request with a valid checksum.
func echo(id uint16, seq byte) []byte {
	//nolint:gosec // G115: ICMP identifier and checksum fields are defined as 16-bit wire values.
	msg := []byte{8, 0, 0, 0, byte(id >> 8), byte(id), 0, seq, 'p', 'i', 'n', 'g'}
	var sum uint32
	for i := 0; i < len(msg); i += 2 {
		//nolint:gosec // G602: index is bounded by a fixed-size QUIC mask or even-length ICMP message.
		sum += uint32(msg[i])<<8 | uint32(msg[i+1])
	}
	sum = sum>>16 + sum&0xffff
	sum += sum >> 16
	//nolint:gosec // G115: ICMP identifier and checksum fields are defined as 16-bit wire values.
	msg[2], msg[3] = byte(^sum>>8), byte(^sum)
	return msg
}

func selfSigned() tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tls.vm.test"}, NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
