package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

type Schema struct {
	Server         string `json:"dns_server"`
	Port           int    `json:"port"`
	Record         string `json:"record"`
	Domain         string `json:"domain"`
	ExpectedOutput string `json:"expected_output"`
}

func Run(ctx context.Context, config string) error {
	schema := Schema{}

	err := json.Unmarshal([]byte(config), &schema)
	if err != nil {
		return err
	}

	connStr := fmt.Sprintf("%s:%d", schema.Server, schema.Port)

	r := new(net.Resolver)
	r.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			return nil, fmt.Errorf("deadline not set")
		}

		d := net.Dialer{
			Deadline: deadline,
		}

		return d.DialContext(ctx, network, connStr)
	}

	var addresses []string

	switch schema.Record {
	case "A":
		ips, err := r.LookupIP(ctx, "ip4", schema.Domain)
		if err != nil {
			return err
		}

		addresses = make([]string, len(ips))
		for i, ip := range ips {
			addresses[i] = ip.String()
		}
	case "AAAA":
		ips, err := r.LookupIP(ctx, "ip6", schema.Domain)
		if err != nil {
			return err
		}

		addresses = make([]string, len(ips))
		for i, ip := range ips {
			addresses[i] = ip.String()
		}
	case "CNAME":
		cname, err := r.LookupCNAME(ctx, schema.Domain)
		if err != nil {
			return err
		}

		addresses = []string{cname}
	case "MX":
		mxs, err := r.LookupMX(ctx, schema.Domain)
		if err != nil {
			return err
		}

		addresses = make([]string, len(mxs))
		for i, mx := range mxs {
			addresses[i] = mx.Host
		}
	case "NS":
		nss, err := r.LookupNS(ctx, schema.Domain)
		if err != nil {
			return err
		}

		addresses = make([]string, len(nss))
		for i, ns := range nss {
			addresses[i] = ns.Host
		}
	case "PTR":
		ptrs, err := r.LookupAddr(ctx, schema.Domain)
		if err != nil {
			return err
		}

		addresses = make([]string, len(ptrs))
		copy(addresses, ptrs)
	case "TXT":
		txts, err := r.LookupTXT(ctx, schema.Domain)
		if err != nil {
			return err
		}

		addresses = make([]string, len(txts))
		copy(addresses, txts)
	default:
		return fmt.Errorf("unsupported record type: %s", schema.Record)
	}

	for _, address := range addresses {
		if address == schema.ExpectedOutput {
			return nil
		}
	}

	return fmt.Errorf("expected out %q not found in [%s]", schema.ExpectedOutput, strings.Join(addresses, ", "))
}
