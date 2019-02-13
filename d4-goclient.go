package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	//BSD 3
	uuid "github.com/satori/go.uuid"
)

const (
	// Version Size
	VERSION_SIZE = 1
	// Type Size
	TYPE_SIZE = 1
	// UUID v4 Size
	UUID_SIZE = 16
	// Timestamp Size
	TIMESTAMP_SIZE = 8
	// HMAC-SHA256 MAC Size
	HMAC_SIZE = 32
	// Payload size Size
	SSIZE = 4

	HDR_SIZE = VERSION_SIZE + TYPE_SIZE + UUID_SIZE + HMAC_SIZE + TIMESTAMP_SIZE + SSIZE
)

type (

	// A d4 writer implements the io.Writer Interface by implementing Write() and Close()
	// it accepts an io.Writer as sink
	d4Writer struct {
		w   io.Writer
		key []byte
		fb  []byte
		pb  []byte
	}

	d4S struct {
		src       io.Reader
		dst       d4Writer
		confdir   string
		cka       time.Duration
		ct        time.Duration
		ce        bool
		retry     time.Duration
		cc        bool
		ca        x509.CertPool
		d4error   uint8
		errnoCopy uint8
		debug     bool
		conf      d4params
	}

	d4params struct {
		uuid        []byte
		snaplen     uint32
		key         []byte
		version     uint8
		source      string
		destination string
		ttype       uint8
	}
)

var (
	// verbose
	buf    bytes.Buffer
	logger = log.New(&buf, "INFO: ", log.Lshortfile)
	infof  = func(info string) {
		logger.Output(2, info)
	}

	tmpct, _    = time.ParseDuration("5mn")
	tmpcka, _   = time.ParseDuration("30s")
	tmpretry, _ = time.ParseDuration("30s")

	confdir = flag.String("c", "", "configuration directory")
	debug   = flag.Bool("v", false, "Set to True, true, TRUE, 1, or t to enable verbose output on stdout")
	ce      = flag.Bool("ce", true, "Set to True, true, TRUE, 1, or t to enable TLS on network destination")
	ct      = flag.Duration("ct", tmpct, "Set timeout in human format")
	cka     = flag.Duration("cka", tmpcka, "Keep Alive time human format, 0 to disable")
	retry   = flag.Duration("rt", tmpretry, "Time in human format before retry after connection failure, set to 0 to exit on failure")
	cc      = flag.Bool("cc", false, "Check TLS certificate againt rootCA.crt")
)

func main() {

	var d4 d4S
	d4p := &d4

	flag.Usage = func() {
		fmt.Printf("d4 - d4 client\n")
		fmt.Printf("Read data from the configured <source> and send it to <destination>\n")
		fmt.Printf("\n")
		fmt.Printf("Usage: d4 -c  config_directory\n")
		fmt.Printf("\n")
		fmt.Printf("Configuration\n\n")
		fmt.Printf("The configuration settings are stored in files in the configuration directory\n")
		fmt.Printf("specified with the -c command line switch.\n\n")
		fmt.Printf("Files in the configuration directory\n")
		fmt.Printf("\n")
		fmt.Printf("key         - is the private HMAC-SHA-256-128 key.\n")
		fmt.Printf("              The HMAC is computed on the header with a HMAC value set to 0\n")
		fmt.Printf("              which is updated later.\n")
		fmt.Printf("snaplen     - the length of bytes that is read from the <source>\n")
		fmt.Printf("version     - the version of the d4 client\n")
		fmt.Printf("type        - the type of data that is send. pcap, netflow, ...\n")
		fmt.Printf("source      - the source where the data is read from\n")
		fmt.Printf("destination - the destination where the data is written to\n")
		fmt.Printf("\n")
		fmt.Printf("-v [TRUE] for verbose output on stdout")
		fmt.Printf("-ce [TRUE] if destination is set to ip:port, use of tls")
		fmt.Printf("-cc [FALSE] if destination is set to ip:port, verification of server's tls certificate againt rootCA.crt")
		fmt.Printf("-ct [300] if destination is set to ip:port, timeout")
		fmt.Printf("-cka [3600] if destination is set to ip:port, keepalive")
		fmt.Printf("-retry [5] if destination is set to ip:port, retry period ")
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NFlag() == 0 || *confdir == "" {
		flag.Usage()
		os.Exit(1)
	} else {
		*confdir = strings.TrimSuffix(*confdir, "/")
		*confdir = strings.TrimSuffix(*confdir, "\\")
	}
	d4.confdir = *confdir
	d4.ce = *ce
	d4.ct = *ct
	d4.cc = *cc
	d4.cka = *cka
	d4.retry = *retry

	// Output logging before closing if debug is enabled
	if *debug == true {
		d4.debug = true
		defer fmt.Print(&buf)
	}

	c := make(chan string)
	for {
		if set(d4p) {
			go d4Copy(d4p, c)
		} else if d4.retry > 0 {
			go func() {
				time.Sleep(d4.retry)
				infof(fmt.Sprintf("Sleeping for %f seconds before retry.\n", d4.retry.Seconds()))
				c <- "done waiting"
			}()
		} else {
			panic("Unrecoverable error without retry.")
		}
		<-c
	}
}

func set(d4 *d4S) bool {
	if d4loadConfig(d4) {
		if setReaderWriters(d4) {
			if d4.dst.initHeader(d4) {
				return true
			}
		}
	}
	return false
}

func d4Copy(d4 *d4S, c chan string) {
	_, err := io.CopyBuffer(&d4.dst, d4.src, d4.dst.pb)
	if err != nil {
		c <- fmt.Sprintf("%s", err)
	}
}

func readConfFile(d4 *d4S, fileName string) []byte {
	f, err := os.OpenFile((*d4).confdir+"/"+fileName, os.O_RDWR|os.O_CREATE, 0666)
	defer f.Close()
	if err != nil {
		log.Fatal(err)
	}
	data := make([]byte, 100)
	count, err := f.Read(data)
	if err != nil {
		if err != io.EOF {
			log.Fatal(err)
		}
	}
	infof(fmt.Sprintf("read %d bytes: %q\n", count, data[:count]))
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
	// trim \n if present
	return bytes.TrimSuffix(data[:count], []byte("\n"))
}

func d4loadConfig(d4 *d4S) bool {
	// populate the map
	(*d4).conf = d4params{}
	(*d4).conf.source = string(readConfFile(d4, "source"))
	(*d4).conf.destination = string(readConfFile(d4, "destination"))
	tmpu, err := uuid.FromString(string(readConfFile(d4, "uuid")))
	if err != nil {
		// generate new uuid
		(*d4).conf.uuid = generateUUIDv4()
		// And push it into the conf file
		f, err := os.OpenFile((*d4).confdir+"/uuid", os.O_WRONLY, 0666)
		defer f.Close()
		if err != nil {
			log.Fatal(err)
		}
		// store as canonical representation
		f.WriteString(fmt.Sprintf("%s", uuid.FromBytesOrNil((*d4).conf.uuid)) + "\n")
	} else {
		(*d4).conf.uuid = tmpu.Bytes()
	}
	// parse snaplen to uint32
	tmp, _ := strconv.ParseUint(string(readConfFile(d4, "snaplen")), 10, 32)
	(*d4).conf.snaplen = uint32(tmp)
	(*d4).conf.key = readConfFile(d4, "key")
	// parse version to uint8
	tmp, _ = strconv.ParseUint(string(readConfFile(d4, "version")), 10, 8)
	(*d4).conf.version = uint8(tmp)
	// parse type to uint8
	tmp, _ = strconv.ParseUint(string(readConfFile(d4, "type")), 10, 8)
	(*d4).conf.ttype = uint8(tmp)
	// Add the custom CA cert in D4 certpool
	if (*d4).cc {
		certb, _ := ioutil.ReadFile((*d4).confdir + "rootCA.crt")
		(*d4).ca = *x509.NewCertPool()
		ok := (*d4).ca.AppendCertsFromPEM(certb)
		if !ok {
			panic("Failed to parse provided root certificate.")
		}
	}
	return true
}

func newD4Writer(writer io.Writer, key []byte) d4Writer {
	return d4Writer{w: writer, key: key}
}

// TODO QUICK IMPLEM, REVISE
func setReaderWriters(d4 *d4S) bool {

	//TODO implement other destination file, fifo unix_socket ...
	switch (*d4).conf.source {
	case "stdin":
		(*d4).src = os.Stdin
	case "pcap":
		f, _ := os.Open("capture.pcap")
		(*d4).src = f
	}
	isn, dstnet := isNet((*d4).conf.destination)
	if isn {
		dial := net.Dialer{
			DualStack:     true,
			Timeout:       (*d4).ct,
			KeepAlive:     (*d4).cka,
			FallbackDelay: 0,
		}
		tlsc := tls.Config{
			InsecureSkipVerify: true,
		}
		if (*d4).cc {
			tlsc = tls.Config{
				InsecureSkipVerify: false,
				RootCAs:            &(*d4).ca,
			}
		}
		if (*d4).ce == true {
			conn, errc := tls.DialWithDialer(&dial, "tcp", dstnet, &tlsc)
			if errc != nil {
				fmt.Println(errc)
				return false
			}
			(*d4).dst = newD4Writer(conn, (*d4).conf.key)
		} else {
			conn, errc := dial.Dial("tcp", dstnet)
			if errc != nil {
				return false
			}
			(*d4).dst = newD4Writer(conn, (*d4).conf.key)
		}
	} else {
		switch (*d4).conf.destination {
		case "stdout":
			(*d4).dst = newD4Writer(os.Stdout, (*d4).conf.key)
		case "file":
			f, _ := os.Create("test.txt")
			(*d4).dst = newD4Writer(f, (*d4).conf.key)
		default:
			panic(fmt.Sprintf("No suitable destination found, given :%q", (*d4).conf.destination))
		}
	}

	// Create the copy buffer
	(*d4).dst.fb = make([]byte, HDR_SIZE+(*d4).conf.snaplen)
	(*d4).dst.pb = make([]byte, (*d4).conf.snaplen)

	return true
}

func isNet(host string) (bool, string) {
	// Check ipv6
	if strings.HasPrefix(host, "[") {
		// Parse an IP-Literal in RFC 3986 and RFC 6874.
		// E.g., "[fe80::1]", "[fe80::1%25en0]", "[fe80::1]:80".
		i := strings.LastIndex(host, "]")
		if i < 0 {
			panic("Unmatched [ in destination config")
		}
		if !validPort(host[i+1:]) {
			panic("No valid port specified")
		}
		// trim brackets

		if net.ParseIP(strings.Trim(host[:i+1], "[]")) != nil {
			infof(fmt.Sprintf("Server IP: %s, Server Port: %s\n", host[:i+1], host[i+1:]))
			return true, host
		}
	} else {
		// Ipv4
		ss := strings.Split(string(host), ":")
		if !validPort(":" + ss[1]) {
			panic("No valid port specified")
		}
		if net.ParseIP(ss[0]) != nil {
			infof(fmt.Sprintf("Server IP: %s, Server Port: %s\n", ss[0], ss[1]))
			return true, host
		}
	}
	return false, host
}

// Reusing code from net.url
// validOptionalPort reports whether port is either an empty string
// or matches /^:\d*$/
func validPort(port string) bool {
	if port == "" {
		return false
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func generateUUIDv4() []byte {
	uuid, err := uuid.NewV4()
	if err != nil {
		log.Fatal(err)
	}
	infof(fmt.Sprintf("UUIDv4: %s\n", uuid))
	return uuid.Bytes()
}

func (d4w *d4Writer) Write(bs []byte) (int, error) {
	// bs is pb
	// zero out moving parts of the frame
	copy(d4w.fb[18:62], make([]byte, 44))
	copy(d4w.fb[62:], make([]byte, 62+len(bs)))
	// update headers
	d4w.updateHeader(len(bs))
	// Copy payload after the header
	copy(d4w.fb[62:62+len(bs)], bs)
	// Now that the packet is complete, compute hmac
	d4w.updateHMAC(len(bs))
	// Eventually write binary in the sink
	err := binary.Write(d4w.w, binary.LittleEndian, d4w.fb[:62+len(bs)])
	return len(bs), err
}

// TODO write go idiomatic err return values
func (d4w *d4Writer) updateHeader(lenbs int) bool {
	timeUnix := time.Now().Unix()
	binary.LittleEndian.PutUint64(d4w.fb[18:26], uint64(timeUnix))
	binary.LittleEndian.PutUint32(d4w.fb[58:62], uint32(lenbs))
	return true
}

func (d4w *d4Writer) updateHMAC(ps int) bool {
	h := hmac.New(sha256.New, d4w.key)
	h.Write(d4w.fb[0:1])
	h.Write(d4w.fb[1:2])
	h.Write(d4w.fb[2:18])
	h.Write(d4w.fb[18:26])
	h.Write(make([]byte, 32))
	h.Write(d4w.fb[58:62])
	h.Write(d4w.fb[62 : 62+ps])
	copy(d4w.fb[26:58], h.Sum(nil))
	return true
}

func (d4w *d4Writer) initHeader(d4 *d4S) bool {
	// zero out the header
	copy(d4w.fb[:HDR_SIZE], make([]byte, HDR_SIZE))
	// put version a type into the header
	d4w.fb[0] = (*d4).conf.version
	d4w.fb[1] = (*d4).conf.ttype
	// put uuid into the header
	copy(d4w.fb[2:18], (*d4).conf.uuid)
	// timestamp
	timeUnix := time.Now().UnixNano()
	binary.LittleEndian.PutUint64(d4w.fb[18:26], uint64(timeUnix))
	// hmac is set to zero during hmac operations, so leave it alone
	// init size of payload at 0
	binary.LittleEndian.PutUint32(d4w.fb[58:62], uint32(0))
	infof(fmt.Sprintf("Initialized a %d bytes header:\n", HDR_SIZE))
	infof(fmt.Sprintf("%b\n", d4w.fb[:HDR_SIZE]))
	return true
}
