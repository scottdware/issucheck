package main

import (
	"flag"
	"fmt"
	"github.com/scottdware/go-junos"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	srx       string
	user      string
	pass      string
	swRelease = map[string]string{
		"R": "FRS/Maintenance release software",
		"B": "Beta release software",
		"I": "Internal release software: Private software release for verifying fixes",
		"S": "Service release software: Released to customers to solve a specific problem",
		"X": "Special (eXception) release software: Released to customers to solve an immediate problem",
	}
	v10dot4R3      = []string{"Do not use ISSU"}
	v10dot4R4Plus  = []string{"NAT", "SIP", "SUNRPC", "SQL", "FTP", "DNS", "MSRPC", "RSH", "TALK", "PPTP", "RTSP", "TFTP", "H.323", "Low Latency Firewall", "MGCP", "SCCP", "VPN", "Logging", "IDP", "AppSecure", "NTP", "PCAP", "Port Mirroring", "GRE/IPIP", "Multicast", "SNMP", "Interface Monitoring", "LACP", "LAG", "JFLOW", "GPRS/GTP/SCTP"}
	v11dot1        = []string{"SIP", "SUNRPC", "SQL", "FTP", "DNS", "MSRPC", "RSH", "TALK", "PPTP", "RTSP", "TFTP", "H.323", "Low Latency Firewall", "MGCP", "SCCP", "VPN", "Logging", "IDP", "AppSecure", "NTP", "PCAP", "Port Mirroring", "GRE/IPIP", "Multicast", "SNMP", "Interface Monitoring", "LACP", "LAG", "JFLOW", "GPRS/GTP/SCTP"}
	v11dot2        = []string{"SUNRPC", "SQL", "FTP", "DNS", "MSRPC", "RSH", "TALK", "PPTP", "RTSP", "TFTP", "H.323", "Low Latency Firewall", "MGCP", "SCCP", "VPN", "Logging", "IDP", "AppSecure", "NTP", "PCAP", "Port Mirroring", "GRE/IPIP", "Multicast", "SNMP", "Interface Monitoring", "LACP", "LAG", "JFLOW", "GPRS/GTP/SCTP"}
	v11dot4R1to4   = []string{"MGCP", "SCCP", "VPN", "Logging", "IDP", "AppSecure", "NTP", "PCAP", "Port Mirroring", "GRE/IPIP", "Multicast", "SNMP", "Interface Monitoring", "LACP", "LAG", "JFLOW", "GPRS/GTP/SCTP"}
	v11dot4R5Plus  = []string{"VPN", "GRE/IPIP", "Multicast", "JFLOW", "GPRS/GTP/SCTP"}
	v12dot1Plus    = []string{"VPN", "GRE/IPIP", "Multicast", "JFLOW", "GPRS/GTP/SCTP"}
	v12dot1X44     = []string{"JFLOW", "GPRS/GTP"}
	v12dot1X45     = []string{"GPRS/GTP"}
	v12dot1X46Plus = []string{"No limitations"}
)

func displayOutput(re int, p junos.RoutingEngine, r string, services []string) {
	fmt.Printf("RE%d:\n", re)
	fmt.Printf("\tModel: %s\n", p.Model)
	fmt.Printf("\tJUNOS Version: %s\n", p.Version)
	fmt.Printf("\tSoftware Release Information: %s\n", r)
	fmt.Printf("\n\tThe following %d services are not supported in ISSU/ICU:\n\n", len(services))
	fmt.Printf("\t%s\n", strings.Join(services, ", "))
}

func init() {
	flag.Usage = func() {
		fmt.Println("issuecheck - Check if an SRX cluster is ready for ISSU (KB17946).")
		fmt.Println("\nUsage: issucheck [OPTIONS]")
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.StringVar(&srx, "srx", "", "SRX to run the check against. If specifying multiple, enclose in quotes, i.e. \"srx240-1 srx1400-2\"")
	flag.StringVar(&user, "user", "", "Username to connect as.")
	flag.StringVar(&pass, "password", "", "Password for authentication.")
	flag.Parse()
}

func main() {
	vrx := regexp.MustCompile(`(\d+)\.(\d+)([RBISX]{1})(\d+)(\.(\d+))?`)

	for _, s := range strings.Split(srx, " ") {
		jnpr, err := junos.NewSession(s, user, pass)
		if err != nil {
			fmt.Println(err)
		}
		defer jnpr.Close()

		alg, _ := jnpr.RunCommand("show security alg status", "xml")
		fmt.Println(alg)

		fmt.Printf("SRX %s has %d routing-engines\n\n", s, jnpr.RoutingEngines)
		for i, d := range jnpr.Platform {
			if !strings.Contains(d.Model, "SRX") {
				fmt.Printf("This device doesn't look to be an SRX (%s). You can only run this script against an SRX.\n", d.Model)
				os.Exit(0)
			}

			versionBreak := vrx.FindStringSubmatch(d.Version)
			maj, _ := strconv.Atoi(versionBreak[1])
			min, _ := strconv.Atoi(versionBreak[2])
			rel := versionBreak[3]
			build, _ := strconv.Atoi(versionBreak[4])
			// spin, _ := strconv.Atoi(versionBreak[6])

			if maj <= 10 && min <= 4 && build <= 3 {
				fmt.Printf("RE%d:\n", i)
				fmt.Printf("\tModel: %s, JUNOS version: %s\n", d.Model, d.Version)
				fmt.Printf("\tSoftware Release Information: %s\n", swRelease[rel])
				fmt.Printf("\t\n%s\n", v10dot4R3)
			}

			if maj == 10 && min == 4 && build >= 4 {
				displayOutput(i, d, swRelease[rel], v10dot4R4Plus)
			}

			if maj == 11 && min == 1 {
				displayOutput(i, d, swRelease[rel], v11dot1)
			}

			if maj == 11 && min == 2 {
				displayOutput(i, d, swRelease[rel], v11dot2)
			}

			if maj == 11 && min == 4 && build <= 4 {
				displayOutput(i, d, swRelease[rel], v11dot4R1to4)
			}

			if maj == 11 && min == 4 && build >= 5 {
				displayOutput(i, d, swRelease[rel], v11dot4R5Plus)
			}

			if maj == 12 && min >= 1 && rel != "X" {
				displayOutput(i, d, swRelease[rel], v12dot1Plus)
			}

			if maj == 12 && min == 1 && rel == "X" && build == 44 {
				displayOutput(i, d, swRelease[rel], v12dot1X44)
			}

			if maj == 12 && min == 1 && rel == "X" && build == 45 {
				displayOutput(i, d, swRelease[rel], v12dot1X45)
			}

			if maj == 12 && min == 1 && rel == "X" && build >= 46 {
				fmt.Printf("RE%d:\n", i)
				fmt.Printf("\tModel: %s, JUNOS version: %s\n", d.Model, d.Version)
				fmt.Printf("\tSoftware Release Information: %s\n", swRelease[rel])
				fmt.Printf("\t\n%s\n", strings.Join(v12dot1X46Plus, ", "))
			}
		}

		fmt.Println("--------------------\n")
	}
}
