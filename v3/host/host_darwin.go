// +build darwin

package host

import (
	"bytes"
	"context"
	"encoding/binary"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"unsafe"

	"github.com/shirou/gopsutil/v3/internal/common"
	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/unix"
)

// from utmpx.h
const user_PROCESS = 7

func HostIDWithContext(ctx context.Context) (string, error) {
	uuid, err := unix.Sysctl("kern.uuid")
	if err != nil {
		return "", err
	}
	return strings.ToLower(uuid), err
}

func numProcs(ctx context.Context) (uint64, error) {
	procs, err := process.PidsWithContext(ctx)
	if err != nil {
		return 0, err
	}
	return uint64(len(procs)), nil
}

func UsersWithContext(ctx context.Context) ([]UserStat, error) {
	utmpfile := "/var/run/utmpx"
	var ret []UserStat

	file, err := os.Open(utmpfile)
	if err != nil {
		return ret, err
	}
	defer file.Close()

	buf, err := ioutil.ReadAll(file)
	if err != nil {
		return ret, err
	}

	u := Utmpx{}
	entrySize := int(unsafe.Sizeof(u))
	count := len(buf) / entrySize

	for i := 0; i < count; i++ {
		b := buf[i*entrySize : i*entrySize+entrySize]

		var u Utmpx
		br := bytes.NewReader(b)
		err := binary.Read(br, binary.LittleEndian, &u)
		if err != nil {
			continue
		}
		if u.Type != user_PROCESS {
			continue
		}
		user := UserStat{
			User:     common.IntToString(u.User[:]),
			Terminal: common.IntToString(u.Line[:]),
			Host:     common.IntToString(u.Host[:]),
			Started:  int(u.Tv.Sec),
		}
		ret = append(ret, user)
	}

	return ret, nil

}

func RegisterInfoWithContext(ctx context.Context) (string, string, error) {
	return "", "", common.ErrNotImplementedError
}

func OSBuildTypeWithContext(ctx context.Context) (string, error) {
	return "", common.ErrNotImplementedError
}

func ProductIDWithContext(ctx context.Context) (string, error) {
	return "", common.ErrNotImplementedError
}

func OSInstallDateTimeWithContext(ctx context.Context) (string, error) {
	return "", common.ErrNotImplementedError
}

func SystemManufactureWithContext(ctx context.Context) (string, string, string, error) {
	return "", "", "", common.ErrNotImplementedError
}

func BIOSVersionWithContext(ctx context.Context) (string, error) {
	return "", common.ErrNotImplementedError
}

func SystemDirectoryWithContext(ctx context.Context) (string, string, error) {
	return "", "", common.ErrNotImplementedError
}

func BootDeviceWithContext(ctx context.Context) (string, error) {
	return "", common.ErrNotImplementedError
}

func InstalledAppListWithContext(ctx context.Context) ([]*AppInfo, error) {
	return nil, common.ErrNotImplementedError
}

func SystemLocaleWithContext(ctx context.Context) (string, error) {
	return "", common.ErrNotImplementedError
}

func InputLocaleWithContext(ctx context.Context) (string, error) {
	return "", common.ErrNotImplementedError
}

func TimeZoneWithContext(ctx context.Context) (string, error) {
	return "", common.ErrNotImplementedError
}

func PageFileLocationWithContext(ctx context.Context) (string, error) {
	return "", common.ErrNotImplementedError
}

func DomainWithContext(ctx context.Context) (string, error) {
	return "", common.ErrNotImplementedError
}

func LogonServerWithContext(ctx context.Context) (string, error) {
	return "", common.ErrNotImplementedError
}

func HotFixListWithContext(ctx context.Context) ([]string, error) {
	return "", common.ErrNotImplementedError
}

func OSUUIDWithContext(ctx context.Context) (string, error) {
	return machineid.ID()
}

func PlatformInformationWithContext(ctx context.Context) (string, string, string, error) {
	platform := ""
	family := ""
	pver := ""

	sw_vers, err := exec.LookPath("sw_vers")
	if err != nil {
		return "", "", "", err
	}

	p, err := unix.Sysctl("kern.ostype")
	if err == nil {
		platform = strings.ToLower(p)
	}

	out, err := invoke.CommandWithContext(ctx, sw_vers, "-productVersion")
	if err == nil {
		pver = strings.ToLower(strings.TrimSpace(string(out)))
	}

	// check if the macos server version file exists
	_, err = os.Stat("/System/Library/CoreServices/ServerVersion.plist")

	// server file doesn't exist
	if os.IsNotExist(err) {
		family = "Standalone Workstation"
	} else {
		family = "Server"
	}

	return platform, family, pver, nil
}

func VirtualizationWithContext(ctx context.Context) (string, string, error) {
	return "", "", common.ErrNotImplementedError
}

func KernelVersionWithContext(ctx context.Context) (string, error) {
	version, err := unix.Sysctl("kern.osrelease")
	return strings.ToLower(version), err
}
