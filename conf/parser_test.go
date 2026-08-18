/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"net/netip"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

const testInput = `
[Interface] 
Address = 10.192.122.1/24 
Address = 10.10.0.1/16 
PrivateKey = 892ea5f95725d35993225213e4038b1760c09fcc6bd962ead334674a2b4a9cec 
ListenPort = 51820  #comments don't matter

[Peer] 
PublicKey   =   04eb9a6bb11fb690d54bcb9fc45572e2ef331e42e5d59463001055b41de12f7591a953443811a846d416f1e2e1db7d3a1ff62c45a1a00db779103c20af62a794ac    
Endpoint = 192.95.5.67:1234 
AllowedIPs = 10.192.122.3/32, 10.192.124.1/24

[Peer] 
PublicKey = 0446f2cef1fd4c06b275786abd492d9b829945ff8b59e3bf7f902304eaac239c2c4f5338b317fdf057784a72de8c1d3f1545f43d63fb94c22ad466bb2dca3ddb18 
Endpoint = [2607:5300:60:6b0::c05f:543]:2468 
AllowedIPs = 10.192.122.4/32, 192.168.0.0/16
PersistentKeepalive = 100

[Peer] 
PublicKey = 04bbb94a4a6ef9590f81de6747cbd658d19af84b72f291f216e650a3eca9c64858cf2419d2b7f7738e45f55f6c46564fbb9603c4c7110e0b3e53fbd1ce28ca679a 
PresharedKey = 9217dc6acba5816ba8871d67ff6684f3245f7dbb622c1a819f2a416384cb7368 
Endpoint = test.wireguard.com:18981 
AllowedIPs = 10.10.10.230/32`

func noError(t *testing.T, err error) bool {
	if err == nil {
		return true
	}
	_, fn, line, _ := runtime.Caller(1)
	t.Errorf("Error at %s:%d: %#v", fn, line, err)
	return false
}

func equal(t *testing.T, expected, actual any) bool {
	if reflect.DeepEqual(expected, actual) {
		return true
	}
	_, fn, line, _ := runtime.Caller(1)
	t.Errorf("Failed equals at %s:%d\nactual   %#v\nexpected %#v", fn, line, actual, expected)
	return false
}

func lenTest(t *testing.T, actualO any, expected int) bool {
	actual := reflect.ValueOf(actualO).Len()
	if reflect.DeepEqual(expected, actual) {
		return true
	}
	_, fn, line, _ := runtime.Caller(1)
	t.Errorf("Wrong length at %s:%d\nactual   %#v\nexpected %#v", fn, line, actual, expected)
	return false
}

func contains(t *testing.T, list, element any) bool {
	listValue := reflect.ValueOf(list)
	for i := 0; i < listValue.Len(); i++ {
		if reflect.DeepEqual(listValue.Index(i).Interface(), element) {
			return true
		}
	}
	_, fn, line, _ := runtime.Caller(1)
	t.Errorf("Error %s:%d\nelement not found: %#v", fn, line, element)
	return false
}

func TestSM2PublicKey(t *testing.T) {
	k, err := parsePrivateKeyHex("892ea5f95725d35993225213e4038b1760c09fcc6bd962ead334674a2b4a9cec")
	if !noError(t, err) {
		return
	}
	equal(t, "048ad9242e3cf86181d5193864ffcbb08018c6b1887dcbcf7496ee08fcb2ecb7ab801e1368e946e9afd84afcd81f90559a7b64dc04fba0cba4a55fbb49bdb40393", k.Public().String())
}

func TestToUAPI(t *testing.T) {
	c, err := FromWgQuick(testInput, "test")
	if !noError(t, err) {
		return
	}
	uapi := c.ToUAPI()
	if !strings.Contains(uapi, "private_key=892ea5f95725d35993225213e4038b1760c09fcc6bd962ead334674a2b4a9cec") {
		t.Fatalf("ToUAPI missing private_key:\n%s", uapi)
	}
	if !strings.Contains(uapi, "public_key=04eb9a6bb11fb690d54bcb9fc45572e2ef331e42e5d59463001055b41de12f7591a953443811a846d416f1e2e1db7d3a1ff62c45a1a00db779103c20af62a794ac") {
		t.Fatalf("ToUAPI missing public_key:\n%s", uapi)
	}
	if !strings.Contains(uapi, "preshared_key=9217dc6acba5816ba8871d67ff6684f3245f7dbb622c1a819f2a416384cb7368") {
		t.Fatalf("ToUAPI missing preshared_key:\n%s", uapi)
	}
	if !strings.Contains(uapi, "replace_peers=true") || !strings.Contains(uapi, "allowed_ip=10.192.122.3/32") {
		t.Fatalf("ToUAPI missing peer fields:\n%s", uapi)
	}
	got, err := FromUAPI(uapi, c)
	if !noError(t, err) {
		return
	}
	equal(t, c.Interface.PrivateKey, got.Interface.PrivateKey)
	equal(t, c.Interface.ListenPort, got.Interface.ListenPort)
	lenTest(t, got.Peers, 3)
	equal(t, c.Peers[0].PublicKey, got.Peers[0].PublicKey)
	equal(t, c.Peers[2].PresharedKey, got.Peers[2].PresharedKey)
	equal(t, c.Interface.Addresses, got.Interface.Addresses)
}

func TestFromWgQuick(t *testing.T) {
	conf, err := FromWgQuick(testInput, "test")
	if noError(t, err) {
		lenTest(t, conf.Interface.Addresses, 2)
		contains(t, conf.Interface.Addresses, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 10, 0, 1}), 16))
		contains(t, conf.Interface.Addresses, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 192, 122, 1}), 24))
		equal(t, "892ea5f95725d35993225213e4038b1760c09fcc6bd962ead334674a2b4a9cec", conf.Interface.PrivateKey.String())
		equal(t, uint16(51820), conf.Interface.ListenPort)

		lenTest(t, conf.Peers, 3)
		lenTest(t, conf.Peers[0].AllowedIPs, 2)
		equal(t, Endpoint{Host: "192.95.5.67", Port: 1234}, conf.Peers[0].Endpoint)
		equal(t, "04eb9a6bb11fb690d54bcb9fc45572e2ef331e42e5d59463001055b41de12f7591a953443811a846d416f1e2e1db7d3a1ff62c45a1a00db779103c20af62a794ac", conf.Peers[0].PublicKey.String())

		lenTest(t, conf.Peers[1].AllowedIPs, 2)
		equal(t, Endpoint{Host: "2607:5300:60:6b0::c05f:543", Port: 2468}, conf.Peers[1].Endpoint)
		equal(t, "0446f2cef1fd4c06b275786abd492d9b829945ff8b59e3bf7f902304eaac239c2c4f5338b317fdf057784a72de8c1d3f1545f43d63fb94c22ad466bb2dca3ddb18", conf.Peers[1].PublicKey.String())
		equal(t, uint16(100), conf.Peers[1].PersistentKeepalive)

		lenTest(t, conf.Peers[2].AllowedIPs, 1)
		equal(t, Endpoint{Host: "test.wireguard.com", Port: 18981}, conf.Peers[2].Endpoint)
		equal(t, "04bbb94a4a6ef9590f81de6747cbd658d19af84b72f291f216e650a3eca9c64858cf2419d2b7f7738e45f55f6c46564fbb9603c4c7110e0b3e53fbd1ce28ca679a", conf.Peers[2].PublicKey.String())
		equal(t, "9217dc6acba5816ba8871d67ff6684f3245f7dbb622c1a819f2a416384cb7368", conf.Peers[2].PresharedKey.String())
	}
}

func TestComments(t *testing.T) {
	const input = `# top of file
# second line

[Interface] # the interface
PrivateKey = 892ea5f95725d35993225213e4038b1760c09fcc6bd962ead334674a2b4a9cec
# which port
ListenPort = 51820 # inline port
Address = 10.0.0.1/24

# the only peer
[Peer]
PublicKey = 04eb9a6bb11fb690d54bcb9fc45572e2ef331e42e5d59463001055b41de12f7591a953443811a846d416f1e2e1db7d3a1ff62c45a1a00db779103c20af62a794ac
AllowedIPs = 0.0.0.0/0 # everything
# trailing note
`
	c, err := FromWgQuick(input, "test")
	if !noError(t, err) {
		return
	}

	equal(t, []string{"# top of file", "# second line", ""}, c.Interface.Comments.Header.Before)
	equal(t, "# the interface", c.Interface.Comments.Header.Suffix)
	equal(t, []string{"# which port"}, c.Interface.Comments.Lines["listenport"].Before)
	equal(t, "# inline port", c.Interface.Comments.Lines["listenport"].Suffix)
	equal(t, []string{"# the only peer"}, c.Peers[0].Comments.Header.Before)
	equal(t, "# everything", c.Peers[0].Comments.Lines["allowedips"].Suffix)
	equal(t, []string{"# trailing note"}, c.TrailingComments)

	c2, err := FromWgQuick("[Interface]\nPrivateKey = 892ea5f95725d35993225213e4038b1760c09fcc6bd962ead334674a2b4a9cec\nPostUp = echo '#1 done'\n", "test")
	if noError(t, err) {
		equal(t, "echo '#1 done'", c2.Interface.PostUp)
		equal(t, "", c2.Interface.Comments.Lines["postup"].Suffix)
	}

	serialized := c.ToWgQuick()
	for _, want := range []string{
		"# top of file\n# second line\n\n[Interface] # the interface\n",
		"# which port\nListenPort = 51820 # inline port\n",
		"# the only peer\n[Peer]\n",
		"AllowedIPs = 0.0.0.0/0 # everything\n",
		"# trailing note\n",
	} {
		if !strings.Contains(serialized, want) {
			t.Errorf("serialized config missing %q in:\n%s", want, serialized)
		}
	}

	reparsed, err := FromWgQuick(serialized, "test")
	if noError(t, err) {
		equal(t, serialized, reparsed.ToWgQuick())
		equal(t, c, reparsed)
	}
}

func TestCommentBlankLines(t *testing.T) {
	const input = `# Header line one

# Header line two
[Interface]
PrivateKey = 892ea5f95725d35993225213e4038b1760c09fcc6bd962ead334674a2b4a9cec

# blank line precedes this comment
ListenPort = 51820
Address = 10.0.0.1/24


# multiple blank lines above collapse to one
[Peer]
PublicKey = 04eb9a6bb11fb690d54bcb9fc45572e2ef331e42e5d59463001055b41de12f7591a953443811a846d416f1e2e1db7d3a1ff62c45a1a00db779103c20af62a794ac
AllowedIPs = 0.0.0.0/0
`
	c, err := FromWgQuick(input, "test")
	if !noError(t, err) {
		return
	}

	equal(t, []string{"# Header line one", "", "# Header line two"}, c.Interface.Comments.Header.Before)
	equal(t, []string{"", "# blank line precedes this comment"}, c.Interface.Comments.Lines["listenport"].Before)
	equal(t, []string{"# multiple blank lines above collapse to one"}, c.Peers[0].Comments.Header.Before)

	serialized := c.ToWgQuick()
	for _, want := range []string{
		"# Header line one\n\n# Header line two\n[Interface]\n",
		"\n# blank line precedes this comment\nListenPort = 51820\n",
		"\n# multiple blank lines above collapse to one\n[Peer]\n",
	} {
		if !strings.Contains(serialized, want) {
			t.Errorf("serialized config missing %q in:\n%s", want, serialized)
		}
	}
	if strings.Contains(serialized, "\n\n\n") {
		t.Errorf("serialized config has a run of blank lines:\n%s", serialized)
	}

	reparsed, err := FromWgQuick(serialized, "test")
	if noError(t, err) {
		equal(t, serialized, reparsed.ToWgQuick())
		equal(t, c, reparsed)
	}
}

func TestCommentRepeatedKey(t *testing.T) {
	const input = `[Interface]
PrivateKey = 892ea5f95725d35993225213e4038b1760c09fcc6bd962ead334674a2b4a9cec
# a

Address = 10.0.0.1/24 # home

# b
Address = 10.0.0.2/24 # work
`
	c, err := FromWgQuick(input, "test")
	if !noError(t, err) {
		return
	}
	lenTest(t, c.Interface.Addresses, 2)
	addr := c.Interface.Comments.Lines["address"]
	equal(t, []string{"# a", "", "# b"}, addr.Before)
	equal(t, "# home # work", addr.Suffix)
	serialized := c.ToWgQuick()
	if !strings.Contains(serialized, "# a\n\n# b\nAddress = 10.0.0.1/24, 10.0.0.2/24 # home # work\n") {
		t.Errorf("merged repeated-key comments wrong in:\n%s", serialized)
	}

	c2, err := FromWgQuick("# one\n[Interface] # h1\nPrivateKey = 892ea5f95725d35993225213e4038b1760c09fcc6bd962ead334674a2b4a9cec\n# two\n[Interface] # h2\nListenPort = 51820\n", "test")
	if noError(t, err) {
		equal(t, []string{"# one", "# two"}, c2.Interface.Comments.Header.Before)
		equal(t, "# h1 # h2", c2.Interface.Comments.Header.Suffix)
	}
}

func TestCommentDefaultValuedKeys(t *testing.T) {
	for _, input := range []string{
		"[Interface]\nPrivateKey = 892ea5f95725d35993225213e4038b1760c09fcc6bd962ead334674a2b4a9cec\n# note\nListenPort = 0 # inline\n",
		"[Interface]\nPrivateKey = 892ea5f95725d35993225213e4038b1760c09fcc6bd962ead334674a2b4a9cec\n# note\nTable = auto # inline\n",
		"[Interface]\nPrivateKey = 892ea5f95725d35993225213e4038b1760c09fcc6bd962ead334674a2b4a9cec\n[Peer]\nPublicKey = 04eb9a6bb11fb690d54bcb9fc45572e2ef331e42e5d59463001055b41de12f7591a953443811a846d416f1e2e1db7d3a1ff62c45a1a00db779103c20af62a794ac\nAllowedIPs = 0.0.0.0/0\n# note\nPersistentKeepalive = off # inline\n",
		"[Interface]\nPrivateKey = 892ea5f95725d35993225213e4038b1760c09fcc6bd962ead334674a2b4a9cec\n[Peer]\nPublicKey = 04eb9a6bb11fb690d54bcb9fc45572e2ef331e42e5d59463001055b41de12f7591a953443811a846d416f1e2e1db7d3a1ff62c45a1a00db779103c20af62a794ac\nAllowedIPs = 0.0.0.0/0\n# note\nPresharedKey = 0000000000000000000000000000000000000000000000000000000000000000\n",
	} {
		c, err := FromWgQuick(input, "test")
		if !noError(t, err) {
			continue
		}
		serialized := c.ToWgQuick()
		if !strings.Contains(serialized, "# note") {
			t.Errorf("comment on a default-valued key was dropped:\n--input--\n%s--output--\n%s", input, serialized)
		}
		reparsed, err := FromWgQuick(serialized, "test")
		if noError(t, err) {
			equal(t, c, reparsed)
		}
	}
}

func TestRedactClearsComments(t *testing.T) {
	input := "[Interface]\nPrivateKey = 892ea5f95725d35993225213e4038b1760c09fcc6bd962ead334674a2b4a9cec # backup SECRET\n" +
		"# note SECRET\n[Peer]\nPublicKey = 04eb9a6bb11fb690d54bcb9fc45572e2ef331e42e5d59463001055b41de12f7591a953443811a846d416f1e2e1db7d3a1ff62c45a1a00db779103c20af62a794ac\nAllowedIPs = 0.0.0.0/0\n# trailing SECRET\n"
	c, err := FromWgQuick(input, "test")
	if !noError(t, err) {
		return
	}
	c.Redact()
	if out := c.ToWgQuick(); strings.Contains(out, "SECRET") {
		t.Errorf("Redact left comment text in output:\n%s", out)
	}
}

func FuzzRoundTrip(f *testing.F) {
	f.Add(testInput)
	f.Add("# top of file\n# second line\n\n[Interface] # the interface\n" +
		"PrivateKey = 892ea5f95725d35993225213e4038b1760c09fcc6bd962ead334674a2b4a9cec\n# which port\n" +
		"ListenPort = 51820 # inline port\nAddress = 10.0.0.1/24\n\n# the only peer\n[Peer]\n" +
		"PublicKey = 04eb9a6bb11fb690d54bcb9fc45572e2ef331e42e5d59463001055b41de12f7591a953443811a846d416f1e2e1db7d3a1ff62c45a1a00db779103c20af62a794ac\nAllowedIPs = 0.0.0.0/0 # everything\n# trailing note\n")
	f.Add("[Interface]\nPrivateKey = 892ea5f95725d35993225213e4038b1760c09fcc6bd962ead334674a2b4a9cec\n# a\n\n" +
		"Address = 10.0.0.1/24 # home\n\n# b\nAddress = 10.0.0.2/24 # work\n")
	f.Add("[Interface]\nPrivateKey = 892ea5f95725d35993225213e4038b1760c09fcc6bd962ead334674a2b4a9cec\n# p\nListenPort = 0 # x\n" +
		"# t\nTable = auto # y\n[Peer]\nPublicKey = 04eb9a6bb11fb690d54bcb9fc45572e2ef331e42e5d59463001055b41de12f7591a953443811a846d416f1e2e1db7d3a1ff62c45a1a00db779103c20af62a794ac\n" +
		"AllowedIPs = 0.0.0.0/0\n# k\nPersistentKeepalive = off # z\n")
	f.Add("[Interface]\nPrivateKey = 892ea5f95725d35993225213e4038b1760c09fcc6bd962ead334674a2b4a9cec\nDNS = 1.1.1.1, home.arpa\nMTU = 1280\n" +
		"# pre\nPreUp = echo a=b #1\nPostUp = ip route add # x\nPreDown = echo down\nPostDown = echo # done\n")

	f.Fuzz(func(t *testing.T, s string) {
		c, err := FromWgQuick(s, "test")
		if err != nil {
			return
		}
		serialized := c.ToWgQuick()
		reparsed, err := FromWgQuick(serialized, "test")
		if err != nil {
			t.Fatalf("reserialized config no longer parses: %v\n%s", err, serialized)
		}
		if got := reparsed.ToWgQuick(); got != serialized {
			t.Errorf("serialization is not idempotent\n--first--\n%s--second--\n%s", serialized, got)
		}
		if !reflect.DeepEqual(c, reparsed) {
			t.Errorf("round-trip changed the parsed config\n--input--\n%s--serialized--\n%s", s, serialized)
		}
		if strings.Contains(serialized, "\n\n\n") {
			t.Errorf("output has consecutive blank lines:\n%s", serialized)
		}
		if strings.HasPrefix(serialized, "\n") {
			t.Errorf("output begins with a blank line:\n%s", serialized)
		}
	})
}

func TestParseEndpoint(t *testing.T) {
	_, err := parseEndpoint("[192.168.42.0:]:51880")
	if err == nil {
		t.Error("Error was expected")
	}
	e, err := parseEndpoint("192.168.42.0:51880")
	if noError(t, err) {
		equal(t, "192.168.42.0", e.Host)
		equal(t, uint16(51880), e.Port)
	}
	e, err = parseEndpoint("test.wireguard.com:18981")
	if noError(t, err) {
		equal(t, "test.wireguard.com", e.Host)
		equal(t, uint16(18981), e.Port)
	}
	e, err = parseEndpoint("[2607:5300:60:6b0::c05f:543]:2468")
	if noError(t, err) {
		equal(t, "2607:5300:60:6b0::c05f:543", e.Host)
		equal(t, uint16(2468), e.Port)
	}
	_, err = parseEndpoint("[::::::invalid:18981")
	if err == nil {
		t.Error("Error was expected")
	}
	_, err = parseEndpoint("::0")
	if err == nil {
		t.Error("Error was expected")
	}
}
