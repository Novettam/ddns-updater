package scaleway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/qdm12/ddns-updater/internal/models"
	"github.com/qdm12/ddns-updater/internal/provider/constants"
	"github.com/qdm12/ddns-updater/internal/provider/errors"
	"github.com/qdm12/ddns-updater/internal/provider/headers"
	"github.com/qdm12/ddns-updater/internal/provider/utils"
	"github.com/qdm12/ddns-updater/pkg/publicip/ipversion"
)

type Provider struct {
	domain     string
	owner      string
	ipVersion  ipversion.IPVersion
	ipv6Suffix netip.Prefix
	secretkey  string
	ttl        int
}

// Scaleway payload structures.
type Changes struct {
	Changes []Change `json:"changes"`
}

type Change struct {
	Set Set `json:"set"`
}

type Set struct {
	IDFields IDFields `json:"id_fields"`
	Records  []Record `json:"records"`
}

type IDFields struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type Record struct {
	ID       string `json:"id"`
	Data     string `json:"data"`
	Name     string `json:"name"`
	Priority int    `json:"priority"`
	TTL      int    `json:"ttl"`
	Type     string `json:"type"`
	Comment  string `json:"comment"`
}

// Scaleway API response structures.
type RecordsResponse struct {
	Records []Record `json:"records"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

func New(data json.RawMessage, domain, owner string,
	ipVersion ipversion.IPVersion, ipv6Suffix netip.Prefix) (
	provider *Provider, err error,
) {
	var providerSpecificSettings struct {
		SecretKey string `json:"secretkey"`
		TTL       int    `json:"ttl"`
	}
	err = json.Unmarshal(data, &providerSpecificSettings)
	if err != nil {
		return nil, fmt.Errorf("json decoding provider specific settings: %w", err)
	}

	err = validateSettings(domain,
		providerSpecificSettings.SecretKey, providerSpecificSettings.TTL)
	if err != nil {
		return nil, fmt.Errorf("validating provider specific settings: %w", err)
	}

	return &Provider{
		domain:     domain,
		owner:      owner,
		ipVersion:  ipVersion,
		ipv6Suffix: ipv6Suffix,
		secretkey:  providerSpecificSettings.SecretKey,
		ttl:        providerSpecificSettings.TTL,
	}, nil
}

func validateSettings(domain, secretkey string, ttl int) (err error) {
	err = utils.CheckDomain(domain)
	if err != nil {
		return fmt.Errorf("%w: %w", errors.ErrDomainNotValid, err)
	}

	switch {
	case secretkey == "":
		return fmt.Errorf("%w", errors.ErrAPISecretNotSet)
	case ttl == 0:
		return fmt.Errorf("%w", errors.ErrTTLNotSet)
	}

	return nil
}

func (p *Provider) String() string {
	return utils.ToString(p.domain, p.owner, constants.Scaleway, p.ipVersion)
}

func (p *Provider) Domain() string {
	return p.domain
}

func (p *Provider) Owner() string {
	return p.owner
}

func (p *Provider) IPVersion() ipversion.IPVersion {
	return p.ipVersion
}

func (p *Provider) IPv6Suffix() netip.Prefix {
	return p.ipv6Suffix
}

func (p *Provider) Proxied() bool {
	return false
}

func (p *Provider) BuildDomainName() string {
	return utils.BuildDomainName(p.owner, p.domain)
}

func (p *Provider) HTML() models.HTMLRow {
	return models.HTMLRow{
		Domain:    fmt.Sprintf("<a href=\"http://%s\">%s</a>", p.BuildDomainName(), p.BuildDomainName()),
		Owner:     p.Owner(),
		Provider:  "<a href=\"https://scaleway.com/\">Scaleway</a>",
		IPVersion: p.ipVersion.String(),
	}
}

// Call Scaleway API to update the DNS record with the new IP address.
// Docs: https://www.scaleway.com/en/developers/api/domains-and-dns/
func (p *Provider) Update(ctx context.Context, client *http.Client, ip netip.Addr) (newIP netip.Addr, err error) {
	u := url.URL{
		Scheme: "https",
		Host:   "api.scaleway.com",
		Path:   "/domain/v2beta1/dns-zones/" + p.domain + "/records",
	}

	payload := buildPayload(p.owner, ip, p.ttl)

	// Marshal the payload into JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("marshaling json: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPatch, u.String(), strings.NewReader(string(jsonData)))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("creating http request: %w", err)
	}

	headers.SetUserAgent(request)
	// add scaleway specific header
	headers.SetXAuthToken(request, p.secretkey)
	// Set the appropriate headers
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return netip.Addr{}, err
	}
	defer response.Body.Close()

	// TODO handle every possible status codes from the provider API, or don't
	if response.StatusCode != http.StatusOK {
		var errorResponse ErrorResponse
		if err := json.NewDecoder(response.Body).Decode(&errorResponse); err != nil {
			return netip.Addr{}, fmt.Errorf("decoding error response: %w", err)
		}
		return netip.Addr{}, fmt.Errorf("%w: %d: %s",
			errors.ErrHTTPStatusNotValid, response.StatusCode, utils.ToSingleLine(errorResponse.Message))
	}

	var goodResponse RecordsResponse
	if err := json.NewDecoder(response.Body).Decode(&goodResponse); err != nil {
		return netip.Addr{}, fmt.Errorf("decoding error response: %w", err)
	}

	return ip, nil
}

func buildPayload(owner string, ip netip.Addr, ttl int) Changes {
	recordType := constants.A
	if ip.Is6() {
		recordType = constants.AAAA
	}

	changes := Changes{
		Changes: []Change{
			{
				Set: Set{
					IDFields: IDFields{
						Type: recordType,
						Name: owner,
					},
					Records: []Record{
						{
							Name:    owner,
							Data:    ip.String(),
							Type:    recordType,
							TTL:     ttl,
							Comment: "Updated by ddns-updater",
						},
					},
				},
			},
		},
	}

	return changes
}
