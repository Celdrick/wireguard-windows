/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"C"
	"log"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/tunnel"
)

//export WireGuardTunnelService
func WireGuardTunnelService(confFile16 *uint16) bool {
	confFile := windows.UTF16PtrToString(confFile16)
	conf.PresetRootDirectory(filepath.Dir(confFile))
	tunnel.UseFixedGUIDInsteadOfDeterministic = true
	err := tunnel.Run(confFile)
	if err != nil {
		log.Printf("Service run error: %v", err)
	}
	return err == nil
}

//export WireGuardGenerateKeypair
func WireGuardGenerateKeypair(publicKey, privateKey *byte) {
	sk, err := conf.NewPrivateKey()
	if err != nil {
		panic(err)
	}
	pk := sk.Public()
	privateKeyArray := unsafe.Slice(privateKey, conf.PrivateKeyLength)
	publicKeyArray := unsafe.Slice(publicKey, conf.PublicKeyLength)
	copy(privateKeyArray, sk[:])
	copy(publicKeyArray, pk[:])
}

func main() {}
