package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/skaldesh/dane/dane_tls"
	"github.com/skaldesh/dane/tlsa"
	"math/rand"
	"os"
	"strings"
	"time"
)

const localDnsAdress = "10.0.0.3:53"
const bankDomain = "app.ilabbank.com"
const tlsPort = "443"
const l4Protocol = "tcp"
const googleDnsAddress = "8.8.8.8:53"
const numberOfAlexaDomains = 10000

var alexa = flag.Bool("alexa", false, "Executes the alexa scanning")

func main() {
	flag.Parse()

	if *alexa {
		domains := getAlexaDomains(true)
		if len(domains) < numberOfAlexaDomains {
			fmt.Printf("not enough alexa domains found in list")
		}

		start := time.Now()
		tlsaRecordsFound, err := tlsa.ScanDomainsForTLSA(tlsPort, l4Protocol, googleDnsAddress, domains)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Found %d TLSA records in %d domains in %fs\n", tlsaRecordsFound, numberOfAlexaDomains,
			time.Now().Sub(start).Seconds())
		return
	}

	tlsaRR, err := tlsa.QueryTLSARR(tlsPort, l4Protocol, bankDomain, localDnsAdress)
	if err != nil {
		panic(err)
	}

	certs, err := dane_tls.RetrieveTLSCertificates(bankDomain, tlsPort)
	if err != nil {
		panic(err)
	}

	if tlsa.ValidateX509WithTLSA(certs, tlsaRR) {
		println("sucess!!!")
	} else {
		println("bogus certificate!!!")
	}
}

func getAlexaDomains(random bool) []string {
	inFile, err := os.Open("alexa.txt")
	if err != nil {
		panic(err)
	}
	defer inFile.Close()
	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)

	domains := make([]string, 0, numberOfAlexaDomains)
	rand.Seed(time.Now().Unix())

	for scanner.Scan() {
		if !random || rand.Float32() > 0.9 {
			s := strings.Split(scanner.Text(), ",")
			if len(s) != 2 {
				fmt.Println("unexpected line format in alexa file")
				os.Exit(1)
			}
			domains = append(domains, s[1])
		}

		if len(domains) == numberOfAlexaDomains {
			break
		}
	}

	return domains
}
