/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func monitorDefaultRoute(family winipcfg.AddressFamily, binder conn.BindSocketToInterface, ourLUID winipcfg.LUID) ([]winipcfg.ChangeCallback, error) {
	lastLUID := winipcfg.LUID(0)
	lastIndex := ^uint32(0)
	doIt := func() error {
		err := findDefaultLUID(family, ourLUID, &lastLUID, &lastIndex)
		if err != nil {
			return err
		}
		blackhole := lastLUID == 0
		if family == windows.AF_INET {
			return binder.BindSocketToInterface4(lastIndex, blackhole)
		}
		return binder.BindSocketToInterface6(lastIndex, blackhole)
	}
	if err := doIt(); err != nil {
		return nil, err
	}
	cbr, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		if route != nil && route.DestinationPrefix.PrefixLength == 0 {
			doIt()
		}
	})
	if err != nil {
		return nil, err
	}
	cbi, err := winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		if notificationType == winipcfg.MibParameterNotification {
			doIt()
		}
	})
	if err != nil {
		cbr.Unregister()
		return nil, err
	}
	return []winipcfg.ChangeCallback{cbr, cbi}, nil
}
