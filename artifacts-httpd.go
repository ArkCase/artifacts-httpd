package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	filepath "path/filepath"
	"strconv"
	"strings"
)

const FILE_SEP = string(os.PathSeparator)

var ROOT_DIR string

func SanitizePath(Path string) string {
	path := filepath.Clean(Path)
	path = strings.TrimPrefix(path, FILE_SEP)
	path = strings.TrimSuffix(path, FILE_SEP)
	return path
}

func GlobalSums() []byte {
	// Spit out the global sums
	out, err := exec.Command("global-sums").Output()
	if err != nil {
		log.Printf("Failed to fetch the global checksums: %v", err)
		return nil
	}

	return out
}

type DirectoryEntry struct {
	Name  string
	IsDir bool
	Size  int64
}

func NewDirectoryEntry(Item os.DirEntry) *DirectoryEntry {
	e := new(DirectoryEntry)
	e.IsDir = Item.IsDir()
	if e.IsDir {
		e.Name = Item.Name() + FILE_SEP
		e.Size = 0
	} else {
		e.Name = Item.Name()
		info, err := Item.Info()
		if err != nil {
			return nil
		}
		e.Size = info.Size()
	}
	return e
}

func ListDirContents(Path string) []byte {
	// Iterate through all contents of the directory
	entries, err := os.ReadDir(Path)
	if err != nil {
		log.Printf("Failed to list the contents for the directory [%s]: %v", Path, err)
		return nil
	}

	m := make(map[string]*DirectoryEntry)
	for _, e := range entries {
		entry := NewDirectoryEntry(e)
		if entry == nil {
			log.Printf("Failed to analyze the directory entry [%s] at [%s]: %v", e.Name(), Path, err)
			return nil
		}
		m[entry.Name] = entry
	}

	json, err := json.Marshal(m)
	if err != nil {
		log.Printf("Failed to encode the directory contents as JSON: %v", err)
		return nil
	}

	return []byte(json)
}

func WriteFile(Path string, Stat os.FileInfo) []byte {
	// Output the file and its size
	fileBytes, err := os.ReadFile(Path)
	if err != nil {
		log.Printf("Failed to read the contents from the file [%s]: %v", Path, err)
		return nil
	}
	return fileBytes
}

func TranslatePath(Path string) string {
	// Translate the given path into the actual, on-disk path
	return ROOT_DIR + FILE_SEP + Path
}

func HandleRequest(rsp http.ResponseWriter, req *http.Request) {

	// Only GET is allowed
	switch req.Method {
	case http.MethodGet:
		break
	default:
		log.Printf("Unsupported %s request received for [%s]", req.Method, req.RequestURI)
		rsp.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Sanitize and clean up the relative path
	path := SanitizePath(req.RequestURI)
	path = strings.TrimPrefix(path, FILE_SEP)
	path = strings.TrimSuffix(path, FILE_SEP)

	if path == "global-sums" {
		data := GlobalSums()
		if data == nil {
			rsp.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Spit out the output
		rsp.Write(data)
		rsp.Header().Set("Content-Type", "application/json")
		rsp.WriteHeader(http.StatusOK)
		return
	}

	// Translate to the actual path
	path = TranslatePath(path)

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Requested a missing path: [%s] (%s)", req.RequestURI, path)
			rsp.WriteHeader(http.StatusNotFound)
		} else if os.IsPermission(err) {
			log.Printf("Requested a forbidden path: [%s] (%s)", req.RequestURI, path)
			rsp.WriteHeader(http.StatusForbidden)
		} else {
			log.Printf("Errors detected while processing the path [%s](%s): %s", req.RequestURI, path, err.Error())
			rsp.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	contentType := ""
	data := []byte("")

	if info.IsDir() {
		data = ListDirContents(path)
		contentType = "application/json"
	} else {
		data = WriteFile(path, info)
		contentType = "application/octet-stream"
	}

	if data == nil {
		rsp.WriteHeader(http.StatusInternalServerError)
		return
	}

	rsp.Write(data)
	rsp.Header().Set("Content-Type", contentType)
}

func ConfigureAddress(TLS bool) string {

	addx := os.Getenv("HTTPD_ADDX")
	if len(addx) <= 0 {
		addx = "0.0.0.0"
	}

	trial := net.ParseIP(addx)
	if trial.To4() == nil {
		log.Fatalf("Invalid listening address [%s]", addx)
	}

	portStr := os.Getenv("HTTPD_PORT")
	if len(portStr) <= 0 {
		if TLS {
			portStr = "8443"
		} else {
			portStr = "8080"
		}
	}

	portNum, err := strconv.ParseInt(portStr, 10, 32)
	if err != nil {
		log.Fatalf("Invalid port number [%s]", portStr)
	}

	return fmt.Sprintf("%s:%d", addx, portNum)
}

func ConfigureTLS(http *http.Server) bool {

	// They must either both be blank, or both be non-blank.
	// If they're non-blank, they must both be regular files
	cert := os.Getenv("HTTPD_CERT")
	pkey := os.Getenv("HTTPD_PKEY")

	if (len(cert) <= 0) && (len(pkey) <= 0) {
		return false
	}

	stat, err := os.Stat(cert)
	if err != nil {
		log.Fatalf("Failed to scan the certificate file at [%s]: %s", cert, err.Error())
	} else if stat.IsDir() {
		log.Fatalf("The path [%s] for the SSL certificate is not a regular file", cert)
	}

	stat, err = os.Stat(pkey)
	if err != nil {
		log.Fatalf("Failed to scan the private key file at [%s]: %s", pkey, err.Error())
	} else if stat.IsDir() {
		log.Fatalf("The path [%s] for the SSL private key is not a regular file", pkey)
	}

	tlsConfig, err := tls.LoadX509KeyPair(cert, pkey)
	if err != nil {
		log.Fatalf("Error loading certificate [%s] and private key [%s]: %v", cert, pkey, err.Error())
	}

	http.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{tlsConfig},
	}

	return true
}

func main() {
	ROOT_DIR = os.Getenv("HTTPD_ROOT")
	if len(ROOT_DIR) <= 0 {
		log.Fatalf("Must provide the root directory to serve files from")
	}

	info, err := os.Stat(ROOT_DIR)
	if err != nil {
		log.Fatalf("Failed to analyze the root directory [%s]: %v", ROOT_DIR, err)
	}

	if !info.IsDir() {
		log.Fatalf("The root path [%s] is not a directory", ROOT_DIR)
	}

	http := http.Server{
		Handler: http.HandlerFunc(HandleRequest),
	}

	useTls := ConfigureTLS(&http)
	http.Addr = ConfigureAddress(useTls)

	tlsStr := ""
	if useTls {
		tlsStr = " (with TLS)"
	}

	log.Printf("Artifacts HTTPD server%s started on %s", tlsStr, http.Addr)

	defer http.Close()

	if useTls {
		log.Fatal(http.ListenAndServeTLS("", ""))
	} else {
		log.Fatal(http.ListenAndServe())
	}
}
