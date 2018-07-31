package main


import (
	"net"
	"fmt"
	"os"
	"flag"
	"bufio"
	"gopkg.in/fatih/pool.v2"
	"crypto/tls"
	"crypto/x509"
	"log"
	"time"
	"encoding/json"
	"strings"
	"encoding/base64"
)

func main() {

	portPtr := flag.String("port", "", "a port number")
	tokenPtr := flag.String("token", "", "a logz.io token")
	flag.Parse()

	port := *portPtr
	token := *tokenPtr

	if port == ""{
		port = os.Getenv("LF_PORT")
	}
	if token == ""{
		token = os.Getenv("LF_TOKEN")
	}


	rootPEM := `-----BEGIN CERTIFICATE-----
MIIENjCCAx6gAwIBAgIBATANBgkqhkiG9w0BAQUFADBvMQswCQYDVQQGEwJTRTEU
MBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFkZFRydXN0IEV4dGVybmFs
IFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBFeHRlcm5hbCBDQSBSb290
MB4XDTAwMDUzMDEwNDgzOFoXDTIwMDUzMDEwNDgzOFowbzELMAkGA1UEBhMCU0Ux
FDASBgNVBAoTC0FkZFRydXN0IEFCMSYwJAYDVQQLEx1BZGRUcnVzdCBFeHRlcm5h
bCBUVFAgTmV0d29yazEiMCAGA1UEAxMZQWRkVHJ1c3QgRXh0ZXJuYWwgQ0EgUm9v
dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALf3GjPm8gAELTngTlvt
H7xsD821+iO2zt6bETOXpClMfZOfvUq8k+0DGuOPz+VtUFrWlymUWoCwSXrbLpX9
uMq/NzgtHj6RQa1wVsfwTz/oMp50ysiQVOnGXw94nZpAPA6sYapeFI+eh6FqUNzX
mk6vBbOmcZSccbNQYArHE504B4YCqOmoaSYYkKtMsE8jqzpPhNjfzp/haW+710LX
a0Tkx63ubUFfclpxCDezeWWkWaCUN/cALw3CknLa0Dhy2xSoRcRdKn23tNbE7qzN
E0S3ySvdQwAl+mG5aWpYIxG3pzOPVnVZ9c0p10a3CitlttNCbxWyuHv77+ldU9U0
WicCAwEAAaOB3DCB2TAdBgNVHQ4EFgQUrb2YejS0Jvf6xCZU7wO94CTLVBowCwYD
VR0PBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wgZkGA1UdIwSBkTCBjoAUrb2YejS0
Jvf6xCZU7wO94CTLVBqhc6RxMG8xCzAJBgNVBAYTAlNFMRQwEgYDVQQKEwtBZGRU
cnVzdCBBQjEmMCQGA1UECxMdQWRkVHJ1c3QgRXh0ZXJuYWwgVFRQIE5ldHdvcmsx
IjAgBgNVBAMTGUFkZFRydXN0IEV4dGVybmFsIENBIFJvb3SCAQEwDQYJKoZIhvcN
AQEFBQADggEBALCb4IUlwtYj4g+WBpKdQZic2YR5gdkeWxQHIzZlj7DYd7usQWxH
YINRsPkyPef89iYTx4AWpb9a/IfPeHmJIZriTAcKhjW88t5RxNKWt9x+Tu5w/Rw5
6wwCURQtjr0W4MHfRnXnJK3s9EK0hZNwEGe6nQY1ShjTK3rMUUKhemPR5ruhxSvC
Nr4TDea9Y355e6cJDUCrat2PisP29owaQgVR1EX1n6diIWgVIEM8med8vSTYqZEX
c4g/VhsxOBi0cQ+azcgOno4uG+GMmIPLHzHxREzGBHNJdmAPx/i9F4BrLunMTA5a
mnkPIAou1Z5jJh5VkpTYghdae9C8x49OhgQ=
-----END CERTIFICATE-----`

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		panic("failed to parse root certificate")
	}

	logzio, err := pool.NewChannelPool(1,10, func() (net.Conn, error) {
		log.Println("Making New Connection")
		return tls.Dial("tcp", "listener.logz.io:5052", &tls.Config{
			RootCAs: roots,
		})
	})

	if err != nil{
		panic(err)
	}

	// Listen for incoming connections.
	l, err := net.Listen("tcp", ":"+(port))
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	// Close the listener when the application closes.
	defer l.Close()
	fmt.Println("Listening on "  + ":" + (port))
	for {
		// Listen for an incoming connection.
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		// Handle connections in a new goroutine.
		go handleRequest(conn, logzio, token)
	}



}
type msg struct{
	Token string `json:"token"`
	Source string `json:"source"`
	ArenaId string `json:"arena_id"`
	BattleId string `json:"battle_id"`
	Message string `json:"message"`
	TimeStamp time.Time `json:"@timestamp"`
	Device string `json:"device"`
	Level string `json:"level"`
	StackTrace string `json:"stackTrace"`
}

func decodeString(s string) string  {
	b ,e :=base64.StdEncoding.DecodeString(s)
	if e != nil{
		return ""
	}
	return string(b)
}
// Handles incoming requests.
func handleRequest(conn net.Conn, p pool.Pool, token string) {

	defer func(){
		log.Println("Connection closed")
		conn.Close()
	}()
	log.Println("Starting new connection")
	reader := bufio.NewReader(conn)
	device := "unknown"
	for {
		// Read the incoming connection into the buffer.
		arrStr, err := reader.ReadString(0)
		if err != nil{
			return
		}
		arrStr = strings.Trim(arrStr,"\u0000")
		arr := strings.Split(arrStr,"|")
		var message = ""
		var level = "Info"
		var stackTrace = ""
		var arena = ""
		var battle = ""
		if len(arr) >= 1{
			message = decodeString(arr[0])
		} else { continue }
		if len(arr) >= 2{
			level = arr[1]
		}
		if len(arr) >= 3{
			stackTrace = arr[2]
		}
		if len(arr) >= 4{
			arena = decodeString(arr[3])
		}
		if len(arr) >= 5{
			battle = decodeString(arr[4])
		}

		if device == "unknown"{
			device = message
			message = "Device Have Become Active"
		}

		msg := msg{Token:token, Message:message,
		TimeStamp:time.Now().UTC(),Level:level,
		Device:device, StackTrace: stackTrace, Source:"client",
		ArenaId:arena, BattleId:battle}
		res, e:= json.Marshal(msg)
		if e != nil{
			log.Println(e)
			continue
		}
		log.Println(string(res))
		for i:=0; i < 3 ; i++{
			conn, err := p.Get()
			if err != nil{ continue }
			if pc, ok := conn.(*pool.PoolConn); ok {
				_,err := conn.Write(res)
				if err != nil{
					log.Println(err)
					pc.MarkUnusable()
					pc.Close()
					continue
				}
				_,err = conn.Write([]byte("\n"))
				if err != nil{
					log.Println(err)
					pc.MarkUnusable()
					pc.Close()
					continue
				}

			}
			conn.Close()
			break
		}

	}
}
