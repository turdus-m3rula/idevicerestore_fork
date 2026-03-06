# idevicerestore

> [!NOTE]
> This is a fork of idevicerestore.  

*A command-line application to restore firmware files to iOS devices.*

## Table of Contents
- [Features](#features)
- [Building](#building)
  - [Prerequisites](#prerequisites)
    - [macOS](#macos)
  - [Configuring the source tree](#configuring-the-source-tree)
  - [Building and installation](#building-and-installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [Links](#links)
- [License](#license)
- [Credits](#credits)

## Features

The idevicerestore application is a full reimplementation of all granular steps
which are performed during the restore of a firmware to a device.

In general, upgrades and downgrades are possible, however subject to
availability of SHSH blobs from Apple for signing the firmware files.

Some key features are:

- **Restore:** Update firmware on iOS devices
- **Firmware:** Use official IPSW firmware archive file or a directory as source
- **Update:** Allows updating the device by default or erasing all data
- **Download:** On demand download of latest available firmware for a device
- **Cache:** Downloaded firmware files are cached locally
- **Custom Firmware:** Restore custom firmware files *(requires bootrom exploit)*
- **Baseband:** Allows you to skip NOR/Baseband upgrade
- **SHSH:** Fetch TSS records and save them as ".shsh" files
- **DFU:** Put devices in pwned DFU mode *(limera1n devices only)*
- **AP Ticket:** Use custom AP ticket from a file
- **Cross-Platform:** Tested on Linux, macOS, Windows and Android platforms
- **History:** Developed since 2010

**WARNING:** This tool can easily __destroy your user data__ irreversibly.

Use with caution and make sure to backup your data before trying to restore.

**In any case, usage is at your own risk.**

## Building

### Prerequisites

You need to have a working compiler (gcc/clang) and development environent
available. This project uses autotools for the build process, allowing to
have common build steps across different platforms.
Only the prerequisites differ and they are described in this section.

#### Preparation for building turdus merula
If you want to enable turdus merula and build, you will need resources. For more information, please see [sep.lol](https://sep.lol).
Then put `resource.tar.zst` to `src/stuff/resource.tar.zst` and run this:
```shell
cd src/stuff/
zstd -d resource.tar.zst
tar -xvf resource.tar
./gen.sh
```


#### macOS

* Make sure the Xcode command line tools are installed.

  **Option X**:
  Use either [MacPorts](https://www.macports.org/)
  or [Homebrew](https://brew.sh/) to install `automake`, `autoconf`, and `libtool`.

  Using MacPorts:
  ```shell
  sudo port install libtool autoconf automake
  ```

  Using Homebrew:
  ```shell
  brew install libtool autoconf automake
  ```

  This `idevicerestore` fork has a few dependencies from the libimobiledevice project.
  You will have to build and install the following:
  * [libplist](https://github.com/libimobiledevice/libplist)
  * [libimobiledevice-glue](https://github.com/libimobiledevice/libimobiledevice-glue)
  * [libusbmuxd](https://github.com/libimobiledevice/libusbmuxd)
  * [libimobiledevice](https://github.com/libimobiledevice/libimobiledevice)
  * [libirecovery](https://github.com/turdus-m3rula/libirecovery)
  * [libtatsu](https://github.com/libimobiledevice/libtatsu)
  
  If you want to enable turdus merula, you also need the following dependency:
  * [libfragmentzip](https://github.com/turdus-m3rula/libfragmentzip)
  * [zstd](https://github.com/facebook/zstd)

  Check their `README.md` for building and installation instructions.


### Configuring the source tree

* **From git**

  If you haven't done already, clone the actual project repository and change into the directory.
  ```shell
  git clone https://github.com/turdus-m3rula/idevicerestore.git
  cd idevicerestore
  ```
  
  - [Preparation](#preparation-for-building-turdus-merula)

  Configure the source tree for building:
  ```shell
  ./autogen.sh
  ```

Both `./configure` and `./autogen.sh` (which generates and calls `configure`) accept a few options, for example `--prefix` to allow
building for a different target folder. You can simply pass them like this:

```shell
./autogen.sh --prefix=/usr/local
```
or
```shell
./configure --prefix=/usr/local
```

If you want to enable turdus merula, please add `--with-turdusmerula` to autogen args.

Once the command is successful, the last few lines of output will look like this:
```
[...]
config.status: creating config.h
config.status: config.h is unchanged
config.status: executing depfiles commands
config.status: executing libtool commands

Configuration for idevicerestore 1.1.0:
-------------------------------------------

  Install prefix: .........: /usr/local

  Now type 'make' to build idevicerestore 1.1.0,
  and then 'make install' for installation.
```

### Building and installation

If you followed all the steps successfully, and `autogen.sh` or `configure` did not print any errors,
you are ready to build the project. This is simply done with

```shell
make
```

If no errors are emitted you are ready for installation. Depending on whether
the current user has permissions to write to the destination directory or not,
you would either run
```shell
make install
```
_OR_
```shell
sudo make install
```

**Important**

On Linux, idevicerestore requires a properly installed [usbmuxd](https://github.com/libimobiledevice/usbmuxd.git)
for the restore procedure. Please make sure that it is either running or
configured to be started automatically as soon as a device is detected
in normal and/or restore mode. If properly installed this will be handled
by udev/systemd.

## Usage

The primary scenario is to restore a new firmware to a device.
First of all attach your device to your machine.

Then simply run:
```shell
idevicerestore --latest
```

This will print a selection of firmware versions that are currently being signed
and can be restored to the attached device. It will then attempt to download and
restore the selected firmware.

By default, an update restore is performed which will preserve user data.

Mind that if the firmware file does not contain a 'Customer Upgrade Install'
variant, an erase restore will be performed.

You can force restoring with erasing all data and basically resetting the device
by using:
```shell
idevicerestore --erase --latest
```

Please consult the usage information or manual page for a full documentation of
available command line options:
```shell
idevicerestore --help
man idevicerestore
```


## Links

* libimobiledevice Homepage: https://libimobiledevice.org/
* Original Repository: https://github.com/libimobiledevice/idevicerestore.git
* Original Repository (Mirror): https://git.libimobiledevice.org/idevicerestore.git

## License

If you build with libhfsplus, this project is licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html), included in the repository in the `COPYING_0` file.
If not, this project is licensed under the [GNU Lesser General Public License v3.0](https://www.gnu.org/licenses/lgpl-3.0.en.html),
also included in the repository in the `COPYING` file.

## Credits

Apple, iPhone, iPad, iPod, iPod Touch, Apple TV, Apple Watch, Mac, iOS,
iPadOS, tvOS, watchOS, and macOS are trademarks of Apple Inc.

This project is an independent software application and has not been
authorized, sponsored, or otherwise approved by Apple Inc.

README Updated on: 2025-09-11
