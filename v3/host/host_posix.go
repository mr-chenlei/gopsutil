// +build linux freebsd openbsd darwin solaris

package host

import (
	"bytes"

	"golang.org/x/sys/unix"
)

func KernelArch() (string, error) {
	var utsname unix.Utsname
	err := unix.Uname(&utsname)
	return string(utsname.Machine[:bytes.IndexByte(utsname.Machine[:], 0)]), err
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
