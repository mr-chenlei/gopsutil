// +build darwin freebsd openbsd

package host

import (
	"context"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// cachedBootTime must be accessed via atomic.Load/StoreUint64
var cachedBootTime uint64

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

func BootTimeWithContext(ctx context.Context) (uint64, error) {
	t := atomic.LoadUint64(&cachedBootTime)
	if t != 0 {
		return t, nil
	}
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return 0, err
	}

	atomic.StoreUint64(&cachedBootTime, uint64(tv.Sec))

	return uint64(tv.Sec), nil
}

func UptimeWithContext(ctx context.Context) (uint64, error) {
	boot, err := BootTimeWithContext(ctx)
	if err != nil {
		return 0, err
	}
	return timeSince(boot), nil
}
