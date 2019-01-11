package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
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
		w        io.Writer
		key      []byte
		d4header []byte
		payload  []byte
	}

	d4S struct {
		src       io.Reader
		dst       d4Writer
		confdir   string
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

	confdir = flag.String("c", "", "configuration directory")
	debug   = flag.Bool("v", false, "Set to True, true, TRUE, 1, or t to enable verbose output on stdout")
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
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NFlag() == 0 || *confdir == "" {
		flag.Usage()
		os.Exit(1)
	}
	d4.confdir = *confdir

	// Output logging before closing if debug is enabled
	if *debug == true {
		d4.debug = true
		defer fmt.Print(&buf)
	}

	if d4loadConfig(d4p) == true {
		if d4.dst.initHeader(d4p) == true {
			d4transfer(d4p)
		}
	}
}

func readConfFile(d4 *d4S, fileName string) []byte {
	f, err := os.Open((*d4).confdir + "/" + fileName)
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
	// removes 1 for \n
	return data[:count-1]
}

func d4loadConfig(d4 *d4S) bool {
	// populate the map
	(*d4).conf = d4params{}
	(*d4).conf.source = string(readConfFile(d4, "source"))
	(*d4).conf.destination = string(readConfFile(d4, "destination"))
	(*d4).conf.uuid = readConfFile(d4, "uuid")
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
	return d4checkConfig(d4)
}

func newD4Writer(writer io.Writer, key []byte) d4Writer {
	return d4Writer{w: writer, key: key}
}

// TODO QUICK IMPLEM, REVISE
func d4checkConfig(d4 *d4S) bool {

	//TODO implement other destination file, fifo unix_socket ...
	switch (*d4).conf.source {
	case "stdin":
		(*d4).src = os.Stdin
	case "pcap":
		f, _ := os.Open("capture.pcap")
		(*d4).src = f
	}

	switch (*d4).conf.destination {
	case "stdout":
		(*d4).dst = newD4Writer(os.Stdout, (*d4).conf.key)
	case "file":
		f, _ := os.Create("test.txt")
		(*d4).dst = newD4Writer(f, (*d4).conf.key)
	}

	if len((*d4).conf.uuid) == 0 {
		// UUID not set, generate a new one
		(*d4).conf.uuid = generateUUIDv4()
		// And push it into the conf file
		f, err := os.OpenFile((*d4).confdir+"/uuid", os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			log.Fatal(err)
		}
		f.WriteString(string((*d4).conf.uuid) + "\n")
		f.Close()
	}

	return true
}

func generateUUIDv4() []byte {
	uuid, err := uuid.NewV4()
	if err != nil {
		log.Fatal(err)
	}
	infof(fmt.Sprintf("UUIDv4: %s\n", uuid))
	return []byte(uuid[:])
}

func d4transfer(d4 *d4S) {
	src := (*d4).src
	dst := (*d4).dst
	buf := make([]byte, (*d4).conf.snaplen)
	varybuf := make([]byte, 0)

	for {
		// Take a slice of snaplen
		nread, err := src.Read(buf)
		if err != nil {
			// if EOF, we just wait for more data
			if err != io.EOF {
				log.Fatal(err)
			} else if (*d4).debug {
				os.Exit(0)
			}
		}
		// And push it into the d4writer -> sink chain
		switch {
		case uint32(nread) == (*d4).conf.snaplen:
			dst.Write(buf)
		case nread > 0 && uint32(nread) < (*d4).conf.snaplen:
			varybuf = append(buf[:nread])
			dst.Write(varybuf)
		}
	}
}

func (d4w *d4Writer) Write(bs []byte) (int, error) {
	d4w.updateHeader(bs)
	d4w.payload = bs
	d4w.updateHMAC()
	// Eventually write binary in the sink
	binary.Write(d4w.w, binary.LittleEndian, append(d4w.d4header, d4w.payload...))
	return len(bs), nil
}

// TODO write go idiomatic err return values
func (d4w *d4Writer) updateHeader(bs []byte) bool {
	// zero out moving parts
	copy(d4w.d4header[18:], make([]byte, 44))
	timeUnix := time.Now().Unix()
	ps := 18
	pe := ps + TIMESTAMP_SIZE
	binary.LittleEndian.PutUint64(d4w.d4header[ps:pe], uint64(timeUnix))
	// hmac is set to zero during hmac operations, so leave it alone
	// still, we move the pointers
	ps = pe
	pe = ps + HMAC_SIZE
	ps = pe
	pe = ps + 4
	// Set payload size
	binary.LittleEndian.PutUint32(d4w.d4header[ps:pe], uint32(len(bs)))
	return true
}

func (d4w *d4Writer) updateHMAC() bool {
	h := hmac.New(sha256.New, d4w.key)
	// version
	h.Write(d4w.d4header[0:1])
	// type
	h.Write(d4w.d4header[1:2])
	// uuid
	h.Write(d4w.d4header[2:18])
	// timestamp
	h.Write(d4w.d4header[18:26])
	// hmac (0)
	h.Write(make([]byte, 32))
	// size
	h.Write(d4w.d4header[58:])
	// payload
	h.Write(d4w.payload)
	// final hmac
	copy(d4w.d4header[26:58], h.Sum(nil))
	return true
}

func (d4w *d4Writer) initHeader(d4 *d4S) bool {
	// zero out the header
	d4w.d4header = make([]byte, HDR_SIZE)
	// put version a type into the header
	d4w.d4header[0] = (*d4).conf.version
	d4w.d4header[1] = (*d4).conf.ttype
	// put uuid into the header
	ps := 2
	pe := ps + UUID_SIZE
	copy(d4w.d4header[ps:pe], (*d4).conf.uuid)
	// timestamp
	timeUnix := time.Now().UnixNano()
	ps = pe
	pe = ps + TIMESTAMP_SIZE
	binary.LittleEndian.PutUint64(d4w.d4header[ps:pe], uint64(timeUnix))
	// hmac is set to zero during hmac operations, so leave it alone
	// still, we move the pointers
	ps = pe
	pe = ps + HMAC_SIZE
	ps = pe
	pe = ps + 4
	// init size of payload at 0
	binary.LittleEndian.PutUint32(d4w.d4header[ps:pe], uint32(0))
	infof(fmt.Sprintf("Initialized a %d bytes header:\n", len(d4w.d4header)))
	infof(fmt.Sprintf("%b\n", d4w.d4header))
	return true
}
