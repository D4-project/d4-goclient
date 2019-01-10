package main

import (
	"bytes"
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
		w io.Writer
	}

	d4S struct {
		src       io.Reader
		dst       io.Writer
		confdir   string
		d4error   uint8
		errnoCopy uint8
		conf      d4params
		//header    d4Header
		d4header []byte
		payload  []byte
	}

	d4params struct {
		uuid        []byte
		snaplen     uint32
		key         string
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

func newD4Writer(writer io.Writer) *d4Writer {
	return &d4Writer{w: writer}
}

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

	// Output logging before closing if debug is enabled
	if *debug == true {
		defer fmt.Print(&buf)
	}

	d4.confdir = *confdir
	//var d4 = d4loadConfig(confdir)
	if d4loadConfig(d4p) == true {
		initHeader(d4p)
		//d4transfer(d4p)
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
	(*d4).conf.key = string(readConfFile(d4, "key"))
	// parse version to uint8
	tmp, _ = strconv.ParseUint(string(readConfFile(d4, "version")), 10, 8)
	(*d4).conf.version = uint8(tmp)
	// parse type to uint8
	tmp, _ = strconv.ParseUint(string(readConfFile(d4, "type")), 10, 8)
	(*d4).conf.ttype = uint8(tmp)
	return d4checkConfig(d4)
}

// QUICK IMPLEM, REVISE
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
		(*d4).dst = newD4Writer(os.Stdout)
	case "file":
		f, _ := os.Create("test.txt")
		(*d4).dst = newD4Writer(f)
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

//TODO turn this ugly mess into a Framer
func initHeader(d4 *d4S) bool {
	// zero out the header
	(*d4).d4header = make([]byte, HDR_SIZE)
	// put version a type into the header
	(*d4).d4header[0] = (*d4).conf.version
	(*d4).d4header[1] = (*d4).conf.ttype
	// put uuid into the header
	ps := 2
	pe := ps + UUID_SIZE
	copy((*d4).d4header[ps:pe], (*d4).conf.uuid)
	// timestamp
	timeUnix := time.Now().UnixNano()
	ps = pe
	pe = ps + TIMESTAMP_SIZE
	binary.LittleEndian.PutUint64((*d4).d4header[ps:pe], uint64(timeUnix))
	// hmac is set to zero during hmac operations, so leave it alone
	// still, we move the pointers
	ps = pe
	pe = ps + HMAC_SIZE
	ps = pe
	pe = ps + 4
	// TODO put nread size instead of snaplen
	binary.LittleEndian.PutUint32((*d4).d4header[ps:pe], (*d4).conf.snaplen)

	// LittleEndian
	// toto := append(make([]byte, 0), byte((*d4).conf.snaplen), byte((*d4).conf.snaplen>>8), byte((*d4).conf.snaplen>>16), byte((*d4).conf.snaplen>>24))
	// BigEndian
	// toto := append(make([]byte, 0), byte((*d4).conf.snaplen>>24), byte((*d4).conf.snaplen>>16), byte((*d4).conf.snaplen>>8), byte((*d4).conf.snaplen))
	// tmpi := binary.BigEndian.Uint32(toto)
	// tmpt := binary.LittleEndian.Uint32(others)
	// fmt.Println(tmpi)
	fmt.Println((*d4).d4header)

	return true
}

func d4transfer(d4 *d4S) {
	src := (*d4).src
	dst := (*d4).dst
	buf := make([]byte, (*d4).conf.snaplen)

	//for {
	//n, _ := src.Read(buf)
	_, _ = src.Read(buf)

	dst.Write(buf)

	// if n > 0 {
	// update the header
	// timestamp

	/* 		h := hmac.New(sha256.New, []byte((*d4).conf.key))
	   		h.Write((*d4).header.version)
	   		h.Write((*d4).header.ttype)
	   		h.Write((*d4).header.uuid)
	   		h.Write((*d4).header.timestamp)
	   		h.Write((*d4).header.hhmac)
	   		h.Write((*d4).header.size)
	   		h.Write([]byte(buf))

	*/ //Add it to the header

	// fmt.Println(base64.StdEncoding.EncodeToString(h.Sum(nil)))

	// Write the packet in the sink
	//}
	//fmt.Println(n)
	//fmt.Println(string(buf))
	//}
	//io.Copy((*d4).dst, (*d4).src)
}

func (d4w *d4Writer) Write(bs []byte) (int, error) {
	d4w.w.Write(bs)
	return len(bs), nil
}

func (d4w *d4Writer) Close() error {
	// nothing ATM
	return nil
}
