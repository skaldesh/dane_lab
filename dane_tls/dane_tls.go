package dane_tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
)

const (
	bankCertFile = "/usr/local/internal-ca/ca.crt"
)

// RetrieveTLSCertificates establishes a TLS connection to the given domain on the given port.
// It then returns the certificates that the peer has presented to us.
// This method trusts, including of course the root store of the host system, also the certificate
// of the online bank, since it is self-signed.
func RetrieveTLSCertificates(domain, port string) (certs []*x509.Certificate, err error) {
	// Get the certificate pool of the host system
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return
	}

	// Read in the self-signed certificate of the bank's website
	bankCerts, err := ioutil.ReadFile(bankCertFile)
	if err != nil {
		return
	}

	// Append the bank certificates to the system certificate pool, in order to trust it
	if !rootCAs.AppendCertsFromPEM(bankCerts) {
		err = errors.New("could not append bank certificate to root store")
		return
	}

	// Now dial up the given domain on the given port
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%s", domain, port), &tls.Config{
		RootCAs: rootCAs,
	})
	if err != nil {
		return
	}
	defer conn.Close()

	// TODO
	// Retrieve the certificates that have been sent from the peer and assign it to our return value 'certs'

	certs = conn.ConnectionState().PeerCertificates

	// TODO_END
	return
}
