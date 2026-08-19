module golang.zx2c4.com/wireguard/windows

go 1.25.0

require (
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e
	golang.org/x/crypto v0.55.0
	golang.org/x/sys v0.47.0
	golang.org/x/text v0.41.0
	golang.zx2c4.com/wireguard v0.0.0
)

require (
	github.com/emmansun/gmsm v0.0.0 // indirect
	golang.org/x/mod v0.38.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace (
	github.com/emmansun/gmsm => ../gmsm
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20260420103851-857e549307fe
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20210224134948-620c54ef6199
	golang.zx2c4.com/wireguard => ../wireguard-go
)
