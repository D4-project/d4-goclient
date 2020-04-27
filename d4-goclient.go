package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	config "github.com/D4-project/d4-golang-utils/config"
	uuid "github.com/D4-project/d4-golang-utils/crypto/hash"
	"github.com/D4-project/d4-golang-utils/inputreader"
	_ "github.com/D4-project/d4-golang-utils/inputreader"
	"github.com/gomodule/redigo/redis"
)

const (
	// VERSION_SIZE
	VERSION_SIZE = 1
	// TYPE_SIZE
	TYPE_SIZE = 1
	// UUID_SIZE
	UUID_SIZE = 16
	// TIMESTAMP_SIZE
	TIMESTAMP_SIZE = 8
	// HMAC_SIZE
	HMAC_SIZE = 32
	// SSIZE payload size size
	SSIZE = 4

	// HDR_SIZE total header size
	HDR_SIZE = VERSION_SIZE + TYPE_SIZE + UUID_SIZE + HMAC_SIZE + TIMESTAMP_SIZE + SSIZE

	// MH_FILE_LIMIT defines in bytes the max size of the json meta header file
	MH_FILE_LIMIT = 100000
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
		src            io.Reader
		dst            d4Writer
		confdir        string
		cka            time.Duration
		ct             time.Duration
		ce             bool
		retry          time.Duration
		rate          time.Duration
		cc             bool
		ca             x509.CertPool
		d4error        uint8
		errnoCopy      uint8
		debug          bool
		conf           d4params
		mhb            *bytes.Buffer
		mh             []byte
		redisInputPool *redis.Pool
		redisCon       redis.Conn
	}

	d4params struct {
		uuid        []byte
		snaplen     uint32
		key         []byte
		version     uint8
		source      string
		destination string
		ttype       uint8
		redisHost   string
		redisPort   string
		redisQueue  string
		redisDB     int
	}
)

var (
	// Verbose mode and logging
	buf    bytes.Buffer
	logger = log.New(&buf, "INFO: ", log.Lshortfile)
	debugger = log.New(&buf, "DEBUG: ", log.Lmicroseconds)
	debugf  = func(debug string) {
		debugger.Println("", debug)
	}

	tmpct, _    = time.ParseDuration("5mn")
	tmpcka, _   = time.ParseDuration("30s")
	tmpretry, _ = time.ParseDuration("30s")
	tmprate, _ = time.ParseDuration("200ms")

	confdir = flag.String("c", "", "configuration directory")
	debug   = flag.Bool("v", false, "Set to True, true, TRUE, 1, or t to enable verbose output on stdout - Don't use in production")
	ce      = flag.Bool("ce", true, "Set to True, true, TRUE, 1, or t to enable TLS on network destination")
	ct      = flag.Duration("ct", tmpct, "Set timeout in human format")
	cka     = flag.Duration("cka", tmpcka, "Keep Alive time human format, 0 to disable")
	retry   = flag.Duration("rt", tmpretry, "Rime in human format before retry after connection failure, set to 0 to exit on failure")
	rate   = flag.Duration("rl", tmprate, "Rate limiter: time in human format before retry after EOF")
	cc      = flag.Bool("cc", false, "Check TLS certificate against rootCA.crt")
)

func main() {

	var d4 d4S
	d4p := &d4

	// Setting up log file
	f, err := os.OpenFile("d4-goclient.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	logger.SetOutput(f)
	logger.Println("Init")

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
		fmt.Printf("redis_d4    - location of redis d4 server\n")
		fmt.Printf("redis_queue - analyzer:type:queueuuid to pop\n")
		fmt.Printf("\n")
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
	d4.rate = *rate

	s := make(chan os.Signal, 1)
	signal.Notify(s, os.Interrupt, os.Kill)
	c := make(chan string)

	// Launching the Rate limiter
    ratelimiter := time.Tick(d4.rate)

	d4.mhb = bytes.NewBuffer(d4.mh)

	for {
		// init or reinit after retry
		if set(d4p) {
			// type 254 requires to send a meta-header first
			if d4.conf.ttype == 254 || d4.conf.ttype == 2 {
				// create a jsonreader
				d4p.dst.hijackHeader()
				// Ugly hack to skip bytes.Buffer WriteTo check that bypasses my fixed lenght buffer
				nread, err := io.CopyBuffer(&d4.dst, struct{ io.Reader }{d4.mhb}, d4.dst.pb)
				if err != nil {
					panic(fmt.Sprintf("Cannot initiate session %s", err))
				}
				logger.Println(fmt.Sprintf("Meta-Header sent: %d bytes", nread))
				d4p.dst.restoreHeader()
			}
			// copy routine
			go d4Copy(d4p, c)
			// Block until the rate limiter allow us to continue
			<-ratelimiter
		} else if d4.retry > 0 {
			go func() {
				logger.Println(fmt.Sprintf("Sleeping for %.f seconds before retry...", d4.retry.Seconds()))
				time.Sleep(d4.retry)
				c <- "done waiting"
			}()
		} else {
			exit(d4p, 1)
		}

		// Block until we catch an event
		select {
		case <-c:
			continue
		case <-s:
			logger.Println("Exiting")
			exit(d4p, 0)
		}
	}
}

func exit(d4 *d4S, exitcode int) {
	// Output debug info in the log before closing if debug is enabled
	if *debug == true {
		(*d4).debug = true
		fmt.Print(&buf)
	}
	os.Exit(exitcode)
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
	nread, err := io.CopyBuffer(&d4.dst, d4.src, d4.dst.pb)
	// Always retry
	if err != nil {
		c <- fmt.Sprintf("D4copy: %s", err)
		return
	}
	c <- fmt.Sprintf("EOF: Nread: %d", nread)
	return
}

func readConfFile(d4 *d4S, fileName string) []byte {
	return config.ReadConfigFile((*d4).confdir, fileName)
}

func d4loadConfig(d4 *d4S) bool {
	// populate the map
	(*d4).conf = d4params{}
	(*d4).conf.source = string(readConfFile(d4, "source"))
	if len((*d4).conf.source) < 1 {
		log.Fatal("Unsupported source")
	}
	if (*d4).conf.source == "d4server" {
		// Parse Input Redis Config
		tmp := config.ReadConfigFile(*confdir, "redis_d4")
		ss := strings.Split(string(tmp), "/")
		if len(ss) <= 1 {
			log.Fatal("Missing Database in Redis input config: should be host:port/database_name")
		}
		(*d4).conf.redisDB, _ = strconv.Atoi(ss[1])
		var ret bool
		ret, ss[0] = config.IsNet(ss[0])
		if ret {
			sss := strings.Split(string(ss[0]), ":")
			(*d4).conf.redisHost = sss[0]
			(*d4).conf.redisPort = sss[1]
		} else {
			log.Fatal("Redis config error.")
		}
		(*d4).conf.redisQueue = string(config.ReadConfigFile(*confdir, "redis_queue"))
	}
	(*d4).conf.destination = string(readConfFile(d4, "destination"))
	if len((*d4).conf.destination) < 1 {
		log.Fatal("Unsupported Destination")
	}
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
	tmp, err := strconv.ParseUint(string(readConfFile(d4, "snaplen")), 10, 32)
	if err != nil || tmp < 1 {
		(*d4).conf.snaplen = uint32(4096)
	} else {
		(*d4).conf.snaplen = uint32(tmp)
	}
	(*d4).conf.key = readConfFile(d4, "key")
	// parse version to uint8
	tmp, _ = strconv.ParseUint(string(readConfFile(d4, "version")), 10, 8)
	if err != nil || tmp < 1 {
		(*d4).conf.version = uint8(1)
	} else {
		(*d4).conf.version = uint8(tmp)
	}
	// parse type to uint8
	tmp, _ = strconv.ParseUint(string(readConfFile(d4, "type")), 10, 8)
	if err != nil || tmp < 1 {
		log.Fatal("Unsupported type")
	} else {
		(*d4).conf.ttype = uint8(tmp)
	}
	// parse meta header file
	data := make([]byte, MH_FILE_LIMIT)
	if tmp == 254 || tmp == 2 {
		file, err := os.Open((*d4).confdir + "/metaheader.json")
		defer file.Close()
		if err != nil {
			panic("Failed to open Meta-Header File.")
		} else {
			if count, err := file.Read(data); err != nil {
				panic("Failed to open Meta-Header File.")
			} else {
				if json.Valid(data[:count]) {
					if checkType(data[:count]) {
						if off, err := file.Seek(0, 0); err != nil || off != 0 {
							panic(fmt.Sprintf("Cannot read Meta-Header file: %s", err))
						} else {
							if err := json.Compact((*d4).mhb, data[:count]); err != nil {
								logger.Println("Failed to compact meta header file")
							}
						}
					} else {
						panic("A Meta-Header File should at least contain a 'type' field.")
					}
				} else {
					panic("Failed to validate open Meta-Header File.")
				}
			}
		}
	}
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

func checkType(b []byte) bool {
	var f interface{}
	if err := json.Unmarshal(b, &f); err != nil {
		return false
	}
	m := f.(map[string]interface{})
	for k, v := range m {
		if k == "type" {
			switch v.(type) {
			case string:
				if v != nil {
					return true
				}
			}
		}
	}
	return false
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
	case "d4server":
		// Create a new redis connection pool
		(*d4).redisInputPool = newPool((*d4).conf.redisHost+":"+(*d4).conf.redisPort, 16)
		var err error
		(*d4).redisCon, err = (*d4).redisInputPool.Dial()
		if err != nil {
			logger.Println("Could not connect to d4 Redis")
			return false
		}
		(*d4).src, err = inputreader.NewLPOPReader(&(*d4).redisCon, (*d4).conf.redisDB, (*d4).conf.redisQueue, int(time.Second*(*d4).retry))
		if err != nil {
			log.Printf("Could not create d4 Redis Descriptor %q \n", err)
			return false
		}
	}
	isn, dstnet := config.IsNet((*d4).conf.destination)
	if isn {
		dial := net.Dialer{
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
				logger.Println(errc)
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

func generateUUIDv4() []byte {
	uuid, err := uuid.NewV4()
	if err != nil {
		log.Fatal(err)
	}
	logger.Println(fmt.Sprintf("UUIDv4: %s\n", uuid))
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
	// put version and type into the header
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
	debugf(fmt.Sprintf("Initialized a %d bytes header:\n", HDR_SIZE))
	debugf(fmt.Sprintf("%b\n", d4w.fb[:HDR_SIZE]))
	return true
}

// We use type 2 to send the meta header
func (d4w *d4Writer) hijackHeader() bool {
	d4w.fb[1] = 2
	return true
}

// Switch back the header to 254
func (d4w *d4Writer) restoreHeader() bool {
	d4w.fb[1] = 254
	return true
}

func newPool(addr string, maxconn int) *redis.Pool {
	return &redis.Pool{
		MaxActive:   maxconn,
		MaxIdle:     3,
		IdleTimeout: 240 * time.Second,
		// Dial or DialContext must be set. When both are set, DialContext takes precedence over Dial.
		Dial: func() (redis.Conn, error) { return redis.Dial("tcp", addr) },
	}
}
