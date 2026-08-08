package libdnsspaceship

import (
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// toLibdnsRR converts a spaceshipRecordUnion (API) to a libdns.Record
func (p *Provider) toLibdnsRR(sr spaceshipRecordUnion, zone string) libdns.Record {
	p.logDebug("toLibdnsRR: sr.Type=%s, sr.Name=%s, sr.Value=%s, sr.TTL=%d, zone=%s",
		sr.Type, sr.Name, sr.Value, sr.TTL, zone)

	// normalize name relative to zone
	name := strings.TrimSuffix(sr.Name, "."+zone)
	name = strings.TrimSuffix(name, ".")
	if name == zone || sr.Name == zone {
		name = ""
	}
	ttl := time.Duration(sr.TTL) * time.Second

	p.logDebug("toLibdnsRR: normalized name=%s, ttl=%v", name, ttl)

	switch strings.ToUpper(sr.Type) {
	case "A", "AAAA":
		if sr.Address != "" {
			if ip, err := netip.ParseAddr(sr.Address); err == nil {
				result := libdns.Address{Name: name, TTL: ttl, IP: ip, ProviderData: sr}
				p.logDebug("toLibdnsRR -> libdns.Address{Name:%s, IP:%s}", name, ip.String())
				return result
			}
		}
	case "TXT":
		result := libdns.TXT{Name: name, TTL: ttl, Text: sr.Value, ProviderData: sr}
		p.logDebug("toLibdnsRR -> libdns.TXT{Name:%s, Text:%s}", name, sr.Value)
		return result
	case "CNAME":
		result := libdns.CNAME{Name: name, TTL: ttl, Target: sr.Cname, ProviderData: sr}
		p.logDebug("toLibdnsRR -> libdns.CNAME{Name:%s, Target:%s}", name, sr.Cname)
		return result
	case "MX":
		result := libdns.MX{Name: name, TTL: ttl, Target: sr.Exchange, Preference: uint16(sr.Preference), ProviderData: sr}
		p.logDebug("toLibdnsRR -> libdns.MX{Name:%s, Target:%s, Pref:%d}", name, sr.Exchange, sr.Preference)
		return result
	case "SRV":
		// extract service/transport from name if present
		service, transport := "", ""
		if sr.Name != "" {
			labels := strings.Split(sr.Name, ".")
			if len(labels) >= 2 {
				service = strings.TrimPrefix(labels[0], "_")
				transport = strings.TrimPrefix(labels[1], "_")
			}
		}
		port := sr.PortInt
		if port == 0 {
			switch pv := sr.Port.(type) {
			case string:
				if v, err := strconv.Atoi(strings.TrimPrefix(pv, "_")); err == nil {
					port = v
				}
			case float64:
				port = int(pv)
			case int:
				port = pv
			}
		}
		result := libdns.SRV{
			Name:         name,
			TTL:          ttl,
			Service:      service,
			Transport:    transport,
			Priority:     uint16(sr.Priority),
			Weight:       uint16(sr.Weight),
			Port:         uint16(port),
			Target:       sr.Target,
			ProviderData: sr,
		}
		p.logDebug("toLibdnsRR -> libdns.SRV{Name:%s, Target:%s, Port:%d}", name, sr.Target, port)
		return result
	case "NS":
		// Use libdns.NS for nameserver records
		result := libdns.NS{Name: name, TTL: ttl, Target: sr.Nameserver, ProviderData: sr}
		p.logDebug("toLibdnsRR -> libdns.NS{Name:%s, Target:%s}", name, sr.Nameserver)
		return result
	case "CAA":
		// Use libdns.CAA as the typed representation
		// convert stored union fields into a libdns.CAA value
		flag := 0
		if sr.Flag != nil {
			flag = *sr.Flag
		}
		var f8 uint8
		if flag < 0 {
			f8 = 0
		} else if flag > 255 {
			f8 = 255
		} else {
			f8 = uint8(flag)
		}
		result := libdns.CAA{Name: name, TTL: ttl, Flags: f8, Tag: sr.Tag, Value: sr.Value, ProviderData: sr}
		p.logDebug("toLibdnsRR -> libdns.CAA{Name:%s, Tag:%s, Value:%s}", name, sr.Tag, sr.Value)
		return result
	case "HTTPS":
		// Convert to libdns.ServiceBinding with scheme "https"
		var params libdns.SvcParams
		if sr.SvcParams != "" {
			if p, err := libdns.ParseSvcParams(sr.SvcParams); err == nil {
				params = p
			}
		}
		target := sr.SvcTarget
		if target == "" {
			target = sr.TargetName
		}
		result := libdns.ServiceBinding{
			Name:         name,
			TTL:          ttl,
			Scheme:       "https",
			Priority:     uint16(sr.SvcPriority),
			Target:       target,
			Params:       params,
			ProviderData: sr,
		}
		p.logDebug("toLibdnsRR -> libdns.ServiceBinding{Name:%s, Target:%s, Priority:%d}", name, target, sr.SvcPriority)
		return result
	}
	// Unsupported
	p.logDebug("toLibdnsRR: unsupported type %s, returning nil", sr.Type)
	return nil
}

// fromLibdnsRR converts a libdns.Record into a spaceshipRecordUnion suitable for create/update
// Returns nil for unsupported record types
func (p *Provider) fromLibdnsRR(lr libdns.Record, zone string) *spaceshipRecordUnion {
	rr := lr.RR()
	p.logDebug("fromLibdnsRR: rr.Type=%s, rr.Name=%s, rr.Data=%s, rr.TTL=%v, zone=%s",
		rr.Type, rr.Name, rr.Data, rr.TTL, zone)

	name := rr.Name

	// certmagic passes generic libdns.RR values for ACME challenge records.
	// Parse known RR types first so TXT/CNAME/etc. are converted into their
	// typed libdns forms instead of being dropped as unsupported.
	if raw, ok := lr.(libdns.RR); ok {
		if parsed, err := raw.Parse(); err == nil {
			if _, stillRaw := parsed.(libdns.RR); !stillRaw {
				return p.fromLibdnsRR(parsed, zone)
			}
		}
	}

	// Spaceship API expects the record name relative to the zone
	if name == "" {
		name = "@"
	}

	rec := spaceshipRecordUnion{ResourceRecordBase: ResourceRecordBase{Name: name, Type: strings.ToUpper(rr.Type), TTL: int(rr.TTL.Seconds())}}

	// MX handled specially
	if mx, ok := lr.(libdns.MX); ok {
		rec.Exchange = mx.Target
		rec.Preference = int(mx.Preference)
		p.logDebug("fromLibdnsRR -> MX: rec.Exchange=%s, rec.Preference=%d", rec.Exchange, rec.Preference)
		return &rec
	}

	// Handle SRV records (both typed and textual)
	if srv, ok := lr.(libdns.SRV); ok {
		// map libdns.SRV fields into the spaceship payload
		rec.Service = "_" + strings.TrimPrefix(srv.Service, "_")
		rec.Protocol = "_" + strings.TrimPrefix(srv.Transport, "_")
		rec.Priority = int(srv.Priority)
		rec.Weight = int(srv.Weight)
		rec.Target = srv.Target
		rec.PortInt = int(srv.Port)
		if rec.PortInt != 0 {
			rec.Port = rec.PortInt
		}
		p.logDebug("fromLibdnsRR -> SRV typed: rec.Service=%s, rec.Protocol=%s, rec.Target=%s, rec.Port=%v",
			rec.Service, rec.Protocol, rec.Target, rec.Port)
		return &rec
	}
	if strings.ToUpper(rr.Type) == "SRV" {
		// Parse textual SRV record
		parts := strings.Fields(rr.Data)
		if len(parts) >= 4 {
			if v, err := strconv.Atoi(parts[0]); err == nil {
				rec.Priority = v
			}
			if v, err := strconv.Atoi(parts[1]); err == nil {
				rec.Weight = v
			}
			if v, err := strconv.Atoi(parts[2]); err == nil {
				rec.PortInt = v
				rec.Port = v
			}
			rec.Target = strings.Join(parts[3:], " ")
		}
		if rr.Name != "" {
			labels := strings.Split(rr.Name, ".")
			if len(labels) >= 2 {
				rec.Service = "_" + strings.TrimPrefix(labels[0], "_")
				rec.Protocol = "_" + strings.TrimPrefix(labels[1], "_")
			}
		}
		p.logDebug("fromLibdnsRR -> SRV textual: rec.Service=%s, rec.Protocol=%s, rec.Target=%s, rec.Port=%v",
			rec.Service, rec.Protocol, rec.Target, rec.Port)
		return &rec
	}

	// Handle NS records (both typed and textual)
	if ns, ok := lr.(libdns.NS); ok {
		rec.Nameserver = ns.Target
		p.logDebug("fromLibdnsRR -> NS typed: rec.Nameserver=%s", rec.Nameserver)
		return &rec
	}
	if strings.ToUpper(rr.Type) == "NS" {
		rec.Nameserver = rr.Data
		p.logDebug("fromLibdnsRR -> NS textual: rec.Nameserver=%s", rec.Nameserver)
		return &rec
	}

	// Handle CAA records (both typed and textual)
	if caa, ok := lr.(libdns.CAA); ok {
		tmpFlag := new(int)
		*tmpFlag = int(caa.Flags)
		rec.Flag = tmpFlag
		rec.Tag = caa.Tag
		rec.Value = caa.Value
		p.logDebug("fromLibdnsRR -> CAA typed: rec.Flag=%d, rec.Tag=%s, rec.Value=%s", *tmpFlag, rec.Tag, rec.Value)
		return &rec
	}
	if strings.ToUpper(rr.Type) == "CAA" {
		parts := strings.Fields(rr.Data)
		if len(parts) >= 3 {
			if v, err := strconv.Atoi(parts[0]); err == nil {
				f := v
				rec.Flag = &f
			}
			rec.Tag = parts[1]
			rec.Value = strings.Join(parts[2:], " ")
		}
		p.logDebug("fromLibdnsRR -> CAA textual: rec.Flag=%v, rec.Tag=%s, rec.Value=%s", rec.Flag, rec.Tag, rec.Value)
		return &rec
	}

	// Handle ServiceBinding (HTTPS) records
	if svc, ok := lr.(libdns.ServiceBinding); ok {
		// Only handle HTTPS records (ServiceBinding with scheme "https")
		if strings.ToLower(svc.Scheme) == "https" {
			rec.Type = "HTTPS"
			rec.SvcPriority = int(svc.Priority)
			rec.TargetName = svc.Target // Use TargetName for API compatibility
			rec.SvcParams = svc.Params.String()
			p.logDebug("fromLibdnsRR -> ServiceBinding (HTTPS): rec.SvcPriority=%d, rec.TargetName=%s, rec.SvcParams=%s",
				rec.SvcPriority, rec.TargetName, rec.SvcParams)
			return &rec
		}
		// For non-HTTPS ServiceBinding records, return nil (unsupported)
		p.logDebug("fromLibdnsRR -> ServiceBinding non-HTTPS scheme %s, returning nil", svc.Scheme)
		return nil
	}

	switch v := lr.(type) {
	case libdns.Address:
		rec.Address = v.IP.String()
		p.logDebug("fromLibdnsRR -> Address: rec.Address=%s", rec.Address)
	case libdns.TXT:
		rec.Value = v.Text
		p.logDebug("fromLibdnsRR -> TXT: rec.Value=%s", rec.Value)
	case libdns.CNAME:
		rec.Cname = v.Target
		p.logDebug("fromLibdnsRR -> CNAME: rec.Cname=%s", rec.Cname)
	case libdns.MX:
		// already handled
	default:
		// Unsupported record type (including libdns.RR)
		p.logDebug("fromLibdnsRR: unsupported type, returning nil")
		return nil
	}
	return &rec
}
