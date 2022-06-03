// Discovery checks if the given domain supports Mailio exchange protocol
// Igor Rendulic, "MIR-5: DNS Discovery [DRAFT]," Mailio Improvement Proposals, no. 5, June 2022. [Online serial].
// Available: https://mirs.mail.io/MIRS/mir-5.
package discovery

import (
	"context"
	"encoding/base64"
	"net"
	"strings"

	"github.com/mailio/go-mailio-core-modules/discovery"
	"github.com/mailio/go-mailio-core-modules/errors"
)

type DiscoveryService struct{}

func NewDiscoverer() *DiscoveryService {
	return &DiscoveryService{}
}

// DNS discovery of the domain.
// Returns Discovery object with the following fields:
// - Domain: domain name
// - IsMailio: true if the domain supports Mailio exchange protocol
// - PublicKeyType: type of the public key (currently only ed25519 is supported)
// - PublicKey: base64 encoded public key
// - Ips: IP addresses of the domain
func (d *DiscoveryService) Discover(ctx context.Context, domain string) (*discovery.Discovery, error) {
	var r net.Resolver

	txts, err := r.LookupTXT(ctx, "mailio._mailiokey."+domain)
	if err != nil {
		return nil, err
	}
	if len(txts) == 0 {
		return nil, errors.ErrNotFound
	}
	ips, err := r.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, err
	}
	// read IP address
	ipAddresses := []string{}
	for _, ip := range ips {
		if ipv4 := ip.IP.To4(); ipv4 != nil {
			ipAddress := ipv4.String()
			ipAddresses = append(ipAddresses, ipAddress)
		}
	}
	// parse TXT record
	for _, txt := range txts {
		if strings.Contains(txt, "v=MAILIO1") {

			disc, err := d.parseTxtV1(txt)
			if err != nil {
				return nil, err
			}
			pkErr := d.validatePublicKey(disc.PublicKey)
			if pkErr != nil {
				return nil, errors.ErrInvalidPublicKey
			}
			disc.Domain = domain
			disc.Ips = ipAddresses
			return disc, nil
		}
	}
	return nil, errors.ErrNotFound
}

// helper parsing function for MAILIO1 (version 1)
func (d *DiscoveryService) parseTxtV1(txt string) (*discovery.Discovery, error) {
	split := strings.Split(txt, ";")
	if len(split) < 3 {
		return nil, errors.ErrInvalidFormat
	}
	keyType := strings.Trim(split[1], " ")
	publicKey := strings.Trim(split[2], " ")

	if !strings.HasPrefix(keyType, "k=") {
		return nil, errors.ErrInvalidFormat
	}
	if !strings.HasPrefix(publicKey, "p=") {
		return nil, errors.ErrInvalidFormat
	}

	return &discovery.Discovery{
		IsMailio:      true,
		PublicKeyType: strings.Replace(keyType, "k=", "", 1),
		PublicKey:     strings.Replace(publicKey, "p=", "", 1),
	}, nil
}

// simple verification of the public key (only checks the length).
func (d *DiscoveryService) validatePublicKey(publicKey string) error {
	pbBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return errors.ErrInvalidFormat
	}
	if len(pbBytes) != 32 {
		return errors.ErrInvalidPublicKey
	}
	return nil
}
