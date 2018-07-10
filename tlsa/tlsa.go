package tlsa

import (
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"time"
	"golang.org/x/time/rate"
	"context"
)

var dnsClient = new(dns.Client)

func init() {
	dnsClient.Timeout = 2 * time.Second
}

// QueryTLSARR requests the TLSA record for the given domain, port, L4-protocol from the DNS
// server at the given address.
func QueryTLSARR(port, layer4Protocol, domain, dnsAddress string) (record *dns.TLSA, err error) {
	// The message we send to the DNS server
	m := new(dns.Msg)

	var fqdn string
	var qType uint16

	// TODO
	// We want to retrieve the TLSA record here, so we must build up a query to the DNS server.
	// An "A" record you would retrieve by setting fqdn to "google.com" for example setting the qType
	// to dane.TypeA
	// Now, do the same stuff for TLSA (remember how the record looks like in the zonefile on PC4
	// if you have difficulties how the fqdn should be structured)

	fqdn = fmt.Sprintf("_%s._%s.%s.", port, layer4Protocol, domain)
	qType = dns.TypeTLSA

	// TODO_END

	// Set the question now to retrieve the TLSA record on the message
	m.SetQuestion(dns.Fqdn(fqdn), qType)
	// Send a synchronous request to the DNS server
	r, _, err := dnsClient.Exchange(m, dnsAddress)
	if err != nil {
		return
	}
	if r.Rcode != dns.RcodeSuccess {
		err = errors.New("rcode was not success")
		return
	}
	// Retrieve the TLSA record from the answer section (there can be at most 1)
	for _, k := range r.Answer {
		if key, ok := k.(*dns.TLSA); ok {
			record = key
			break
		}
	}
	if record == nil {
		err = errors.New("no record found")
	}

	return
}

func ScanDomainsForTLSA(port, layer4Protocol, dnsAddress string, domains []string) (found int, err error) {
	dnsClient = new(dns.Client)
	dnsClient.Timeout = 2 * time.Second

	conn, err := dnsClient.Dial(dnsAddress)
	if err != nil {
		return
	}
	defer conn.Close()

	limiter := rate.NewLimiter(200, 50)
	ctx := context.Background()

	queryIds := make(map[uint16]string, len(domains))
	m := new(dns.Msg)
	go func() {
		for i, domain := range domains {
			m.Id = uint16(i)
			m.SetQuestion(dns.Fqdn(fmt.Sprintf("_%s._%s.%s.", port, layer4Protocol, domain)), dns.TypeTLSA)

			limiter.Wait(ctx)
			err := conn.WriteMsg(m)
			if err == nil {
				queryIds[m.Id] = domain
			} else {
				println(err.Error())
			}
		}
	}()

	var msg *dns.Msg

outerLoop:
	for {
		msg, err = conn.ReadMsg()
		if err != nil {
			return
		}

		if msg.Rcode != dns.RcodeSuccess {
			continue
		}
		// Retrieve the TLSA record from the answer section (there can be at most 1)
		for _, k := range msg.Answer {
			if _, ok := k.(*dns.TLSA); ok {
				print(queryIds[msg.Id])
				print(" => ")
				println("YES")
				found++
				continue outerLoop
			}
		}

		print(queryIds[msg.Id])
		print(" => ")
		println("NO")
	}

	return
}

// ValidateX509WithTLSA simply verifies each certificate with the Verify() method from the
// github.com/miekg/dns library
// If any of the certificates can not be verified with the tlsa record, false is returned.
func ValidateX509WithTLSA(certs []*x509.Certificate, tlsa *dns.TLSA) bool {
	for _, cert := range certs {
		if tlsa.Verify(cert) != nil {
			return false
		}
	}
	return true
}
