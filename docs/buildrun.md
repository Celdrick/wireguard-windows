# Building, Running, and Developing

### Building

Windows 10 64-bit or Windows Server 2019, and Git for Windows is required. The build script will take care of downloading, verifying, and extracting the right versions of the various dependencies:

```text
C:\Projects> git clone https://git.zx2c4.com/wireguard-windows
C:\Projects> cd wireguard-windows
C:\Projects\wireguard-windows> build
```

### Running

After you've built the application, run `amd64\wireguard.exe` together with
the matching `amd64\wintun.dll` (keep them in the same directory) to install
the manager service and show the UI.

```text
C:\Projects\wireguard-windows> amd64\wireguard.exe
```

WireGuard-GM uses userspace cryptography (SM2/SM3/SM4-GCM) and the Wintun
adapter driver. Wintun is Microsoft-signed; copy `wintun.dll` next to
`wireguard.exe`. This build does **not** install or use WireGuardNT.

### Optional: Localizing

To translate WireGuard UI to your language:

1. Upgrade `resources.rc` accordingly. Follow the pattern.

2. Make a new directory in `locales\` containing the language ID:

  ```text
  C:\Projects\wireguard-windows> mkdir locales\<langID>
  ```

3. Configure and run `build` to prepare initial `locales\<langID>\messages.gotext.json` file:

   ```text
   C:\Projects\wireguard-windows> set GoGenerate=yes
   C:\Projects\wireguard-windows> build
   C:\Projects\wireguard-windows> copy locales\<langID>\out.gotext.json locales\<langID>\messages.gotext.json
   ```

4. Translate `locales\<langID>\messages.gotext.json`. See other language message files how to translate messages and how to tackle plural. For this step, the project is currently using [CrowdIn](https://crowdin.com/translate/WireGuard); please make sure your translations make it there in order to be added here.

5. Run `build` from the step 3 again, and test.

6. Repeat from step 4.

### Optional: Creating the Installer

The installer build script will take care of downloading, verifying, and extracting the right versions of the various dependencies:

```text
C:\Projects\wireguard-windows> cd installer
C:\Projects\wireguard-windows\installer> build
```

### Optional: Signing Binaries

Add a file called `sign.bat` in the root of this repository with these contents, or similar:

```text
set SigningProvider=/sha1 1b3afa5e2a76bb51f00020002dccadb165689c33
set TimestampServer=http://timestamp.digicert.com
```

After, run the above `build` commands as usual, from a shell that has [`signtool.exe`](https://docs.microsoft.com/en-us/windows/desktop/SecCrypto/signtool) in its `PATH`, such as the Visual Studio 2017 command prompt.

### Alternative: Building from Linux

You must first have Mingw and ImageMagick installed, plus sibling checkouts of
`wireguard-go` (GM) and `gmsm`:

```text
$ sudo apt install mingw-w64 imagemagick
$ ls ../wireguard-go ../gmsm
$ make
```

You can deploy the 64-bit build to an SSH host specified by the `DEPLOYMENT_HOST` environment variable (default "winvm") to the remote directory specified by the `DEPLOYMENT_PATH` environment variable (default "Desktop") by using the `deploy` target:

```text
$ make deploy
```

Use `wg-gm` from the wireguard-go tree to talk to a running tunnel's UAPI named
pipe. Standard `wg(8)` expects base64 Curve25519 keys and will not work.

When building on Windows, the aforementioned `build.bat` script takes care of building this.
