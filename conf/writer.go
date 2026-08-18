/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"fmt"
	"strings"
)

func (conf *Config) ToWgQuick() string {
	var output strings.Builder

	writeLine := func(c Comments, line string) {
		for _, before := range c.Before {
			output.WriteString(before)
			output.WriteByte('\n')
		}
		output.WriteString(line)
		if len(c.Suffix) != 0 {
			output.WriteByte(' ')
			output.WriteString(c.Suffix)
		}
		output.WriteByte('\n')
	}
	writeField := func(comments SectionComments, key string, present bool, value any) {
		c := comments.Lines[strings.ToLower(key)]
		if !present && len(c.Before) == 0 && len(c.Suffix) == 0 {
			return
		}
		writeLine(c, key+" = "+fmt.Sprint(value))
	}

	writeLine(conf.Interface.Comments.Header, "[Interface]")
	writeField(conf.Interface.Comments, "PrivateKey", true, conf.Interface.PrivateKey.String())
	writeField(conf.Interface.Comments, "ListenPort", conf.Interface.ListenPort > 0, conf.Interface.ListenPort)

	if len(conf.Interface.Addresses) > 0 {
		addrStrings := make([]string, len(conf.Interface.Addresses))
		for i, address := range conf.Interface.Addresses {
			addrStrings[i] = address.String()
		}
		writeField(conf.Interface.Comments, "Address", true, strings.Join(addrStrings, ", "))
	}

	if len(conf.Interface.DNS)+len(conf.Interface.DNSSearch) > 0 {
		addrStrings := make([]string, 0, len(conf.Interface.DNS)+len(conf.Interface.DNSSearch))
		for _, address := range conf.Interface.DNS {
			addrStrings = append(addrStrings, address.String())
		}
		addrStrings = append(addrStrings, conf.Interface.DNSSearch...)
		writeField(conf.Interface.Comments, "DNS", true, strings.Join(addrStrings, ", "))
	}

	writeField(conf.Interface.Comments, "MTU", conf.Interface.MTU > 0, conf.Interface.MTU)
	writeField(conf.Interface.Comments, "PreUp", len(conf.Interface.PreUp) > 0, conf.Interface.PreUp)
	writeField(conf.Interface.Comments, "PostUp", len(conf.Interface.PostUp) > 0, conf.Interface.PostUp)
	writeField(conf.Interface.Comments, "PreDown", len(conf.Interface.PreDown) > 0, conf.Interface.PreDown)
	writeField(conf.Interface.Comments, "PostDown", len(conf.Interface.PostDown) > 0, conf.Interface.PostDown)

	table := "auto"
	if conf.Interface.TableOff {
		table = "off"
	}
	writeField(conf.Interface.Comments, "Table", conf.Interface.TableOff, table)

	for _, peer := range conf.Peers {
		output.WriteByte('\n')
		writeLine(peer.Comments.Header, "[Peer]")
		writeField(peer.Comments, "PublicKey", true, peer.PublicKey.String())
		writeField(peer.Comments, "PresharedKey", !peer.PresharedKey.IsZero(), peer.PresharedKey.String())

		if len(peer.AllowedIPs) > 0 {
			addrStrings := make([]string, len(peer.AllowedIPs))
			for i, address := range peer.AllowedIPs {
				addrStrings[i] = address.String()
			}
			writeField(peer.Comments, "AllowedIPs", true, strings.Join(addrStrings, ", "))
		}

		writeField(peer.Comments, "Endpoint", !peer.Endpoint.IsEmpty(), peer.Endpoint.String())
		writeField(peer.Comments, "PersistentKeepalive", peer.PersistentKeepalive > 0, peer.PersistentKeepalive)
	}

	for _, comment := range conf.TrailingComments {
		output.WriteString(comment)
		output.WriteByte('\n')
	}
	return output.String()
}

func (conf *Config) ToUAPI() string {
	var output strings.Builder
	output.WriteString(fmt.Sprintf("private_key=%s\n", conf.Interface.PrivateKey.String()))
	if conf.Interface.ListenPort > 0 {
		output.WriteString(fmt.Sprintf("listen_port=%d\n", conf.Interface.ListenPort))
	}
	if len(conf.Peers) > 0 {
		output.WriteString("replace_peers=true\n")
	}
	for _, peer := range conf.Peers {
		output.WriteString(fmt.Sprintf("public_key=%s\n", peer.PublicKey.String()))
		if !peer.PresharedKey.IsZero() {
			output.WriteString(fmt.Sprintf("preshared_key=%s\n", peer.PresharedKey.String()))
		}
		if !peer.Endpoint.IsEmpty() {
			output.WriteString(fmt.Sprintf("endpoint=%s\n", peer.Endpoint.String()))
		}
		output.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.PersistentKeepalive))
		if len(peer.AllowedIPs) > 0 {
			output.WriteString("replace_allowed_ips=true\n")
			for _, address := range peer.AllowedIPs {
				output.WriteString(fmt.Sprintf("allowed_ip=%s\n", address.String()))
			}
		}
	}
	return output.String()
}
