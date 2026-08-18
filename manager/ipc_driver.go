/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

func uapiPath(tunnelName string) string {
	return `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\` + tunnelName
}

func uapiGet(tunnelName string) (string, error) {
	conn, err := namedpipe.DialTimeout(uapiPath(tunnelName), 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("get=1\n\n")); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			if bytes.Contains(buf.Bytes(), []byte("\n\n")) || bytes.Contains(buf.Bytes(), []byte("errno=")) {
				break
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return buf.String(), nil
}

func releaseDriverAdapter(tunnelName string) {
	// Userspace WireGuard-GM has no kernel adapter handle to release.
}

func runtimeConfigError(tunnelName string, err error) error {
	return fmt.Errorf("unable to query runtime configuration for %s: %w", tunnelName, err)
}
