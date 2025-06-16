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
	"time"
)

const FILE_SEP = string(os.PathSeparator)

var ROOT_DIR string

type FileInfo struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	Path     string `json:"path"`
	Version  string `json:"version"`
	Checksum string `json:"checksum"`
	Mtime    string `json:"mtime"`
}

type DirListEntry struct {
	Name string `json:"name"`
}

type DirList struct {
	Name        string         `json:"name"`
	Files       []DirListEntry `json:"files"`
	Directories []DirListEntry `json:"directories"`
}

type Response struct {
	Rc          int    `json:"rc"`
	Msg         string `json:"msg"`
	Data        any    `json:"data"`
	contentType string
	fileData    []byte
}

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

func ReadFile(Path string) []byte {
	// Output the file and its size
	fileBytes, err := os.ReadFile(Path)
	if err != nil {
		log.Printf("Failed to read the contents from the file [%s]: %v", Path, err)
		return nil
	}
	return fileBytes
}

func FileExists(Path string) bool {
	// Output the file and its size
	_, err := os.Stat(Path)
	return (err == nil)
}

func ListDirContents(Path string) *DirList {

	// Iterate through all contents of the directory
	entries, err := os.ReadDir(Path)
	if err != nil {
		log.Printf("Failed to list the contents for the directory [%s]: %v", Path, err)
		return nil
	}

	list := new(DirList)
	list.Name = filepath.Base(Path)
	list.Directories = []DirListEntry{}
	list.Files = []DirListEntry{}

	for _, e := range entries {
		entry := new(DirListEntry)
		entry.Name = e.Name()
		if e.IsDir() {
			list.Directories = append(list.Directories, *entry)
		} else if strings.HasSuffix(entry.Name, ".sum") {
			// If this is associated to a parent file, ignore it
			parent := Path + FILE_SEP + strings.TrimSuffix(entry.Name, ".sum")
			if _, err := os.Stat(parent); os.IsNotExist(err) {
				list.Files = append(list.Files, *entry)
			}
		} else if strings.HasSuffix(entry.Name, ".ver") {
			// If this is associated to a parent file, ignore it
			parent := Path + FILE_SEP + strings.TrimSuffix(entry.Name, ".ver")
			if _, err := os.Stat(parent); os.IsNotExist(err) {
				list.Files = append(list.Files, *entry)
			}
		} else {
			list.Files = append(list.Files, *entry)
		}
	}
	return list
}

func GetFileInfo(Path string) *FileInfo {
	stat, err := os.Stat(Path)
	if err != nil {
		log.Printf("Failed to Stat the file at [%s]: %s", Path, err.Error())
		return nil
	}

	info := new(FileInfo)
	info.Name = stat.Name()
	info.Size = stat.Size()
	info.Path = Path
	info.Mtime = stat.ModTime().UTC().Format(time.RFC3339)

	info.Version = ""
	f := Path + ".ver"
	if FileExists(f) {
		data := ReadFile(f)
		if data != nil {
			info.Version = string(data)
		}
	}

	info.Checksum = ""
	f = Path + ".sum"
	if FileExists(f) {
		data := ReadFile(f)
		if data != nil {
			info.Checksum = string(data)
		}
	}

	return info
}

func TranslatePath(Path string) string {
	// Translate the given path into the actual, on-disk path
	return ROOT_DIR + FILE_SEP + Path
}

func HandlePath(Path string, rsp http.ResponseWriter, req *http.Request) *Response {

	response := new(Response)

	// Only GET is allowed
	switch req.Method {
	case http.MethodGet:
		break
	default:
		response.Msg = fmt.Sprintf("Unsupported %s request received for [%s]", req.Method, req.RequestURI)
		response.Rc = http.StatusMethodNotAllowed
		return response
	}

	cmd := req.URL.Query().Get("cmd")
	switch cmd {
	case "list":
	case "info":
	case "download":
		break
	case "":
		cmd = "download"

	default:
		response.Msg = fmt.Sprintf("Unsupported command [%s] received for [%s]", cmd, req.RequestURI)
		response.Rc = http.StatusBadRequest
		return response
	}

	// Translate to the actual path
	Path = TranslatePath(Path)

	info, err := os.Stat(Path)
	if err != nil {
		if os.IsNotExist(err) {
			response.Rc = http.StatusNotFound
			response.Msg = fmt.Sprintf("Path not found [%s] -> [%s]", req.RequestURI, Path)
		} else if os.IsPermission(err) {
			response.Rc = http.StatusForbidden
			response.Msg = fmt.Sprintf("Access denied [%s] -> [%s]", req.RequestURI, Path)
		} else {
			response.Rc = http.StatusInternalServerError
			response.Msg = fmt.Sprintf("Internal server error while processing the %s request for [%s] (%s): %s", cmd, req.RequestURI, Path, err.Error())
		}
		return response
	}

	if info.IsDir() {
		response.Data = ListDirContents(Path)
		response.contentType = "application/json"
	} else if cmd == "download" {
		response.fileData = ReadFile(Path)
		response.contentType = "application/octet-stream"
	} else {
		response.Data = GetFileInfo(Path)
		response.contentType = "application/json"
	}

	if (response.Data == nil) && (response.fileData == nil) {
		response.Rc = http.StatusInternalServerError
		response.Msg = fmt.Sprintf("Internal Server Error (no data to be returned for [%s])", Path)
	} else {
		response.Rc = http.StatusOK
		response.Msg = "OK"
	}

	return response
}

func HandleRequest(rsp http.ResponseWriter, req *http.Request) {

	// Sanitize and clean up the relative path
	path := strings.TrimPrefix(req.URL.Path, "/api/1")

	path = SanitizePath(path)
	path = strings.TrimPrefix(path, FILE_SEP)
	path = strings.TrimSuffix(path, FILE_SEP)

	// We don't care if the command is list or download - always produce the output
	var data []byte
	var err error
	response := new(Response)
	if path == "global-sums" {
		data = GlobalSums()
		if data == nil {
			rsp.WriteHeader(http.StatusInternalServerError)
			return
		}

		response.Rc = http.StatusOK
		response.contentType = "application/json"
	} else {
		response = HandlePath(path, rsp, req)
		if response == nil {
			log.Printf("Failed to obtain a response object")
			rsp.WriteHeader(http.StatusInternalServerError)
			return
		}

		if response.Rc != http.StatusOK {
			log.Printf(response.Msg)
			rsp.WriteHeader(response.Rc)
			return
		}

		if response.fileData != nil {
			data = response.fileData
		} else {
			data, err = json.Marshal(response)
			if err != nil {
				log.Printf("Failed to marshal the JSON for the response: %s", err.Error())
				rsp.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
	}

	rsp.Header().Set("Content-Type", response.contentType)
	rsp.WriteHeader(response.Rc)
	rsp.Write(data)
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
