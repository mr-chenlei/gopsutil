// +build windows

package host

import (
	"context"
	"fmt"
	"github.com/denisbrodbeck/machineid"
	"github.com/digitalocean/go-smbios/smbios"
	"golang.org/x/sys/windows/registry"
	"math"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/StackExchange/wmi"
	"github.com/shirou/gopsutil/v3/internal/common"
	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows"
)

var (
	procGetSystemTimeAsFileTime = common.Modkernel32.NewProc("GetSystemTimeAsFileTime")
	procGetTickCount32          = common.Modkernel32.NewProc("GetTickCount")
	procGetTickCount64          = common.Modkernel32.NewProc("GetTickCount64")
	procGetNativeSystemInfo     = common.Modkernel32.NewProc("GetNativeSystemInfo")
	procRtlGetVersion           = common.ModNt.NewProc("RtlGetVersion")
	procGetTimeZoneInformation  = common.Modkernel32.NewProc("GetTimeZoneInformation")
	procGetSystemTime           = common.Modkernel32.NewProc("GetSystemTime")
	procNetGetJoinInformation   = common.ModNet.NewProc("NetGetJoinInformation")
	procNetApiBufferFree        = common.ModNet.NewProc("NetApiBufferFree")
	procGetLocaleInfo           = common.Modkernel32.NewProc("GetLocaleInfoW")
	procSHLoadIndirectString    = common.ModShl.NewProc("SHLoadIndirectString")
	procGetKeyboardLayout       = common.ModUser.NewProc("GetKeyboardLayout")
	procGetSystemDirectoryA     = common.Modkernel32.NewProc("GetSystemDirectoryA")
)

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ns-wdm-_osversioninfoexw
type osVersionInfoExW struct {
	dwOSVersionInfoSize uint32
	dwMajorVersion      uint32
	dwMinorVersion      uint32
	dwBuildNumber       uint32
	dwPlatformId        uint32
	szCSDVersion        [128]uint16
	wServicePackMajor   uint16
	wServicePackMinor   uint16
	wSuiteMask          uint16
	wProductType        uint8
	wReserved           uint8
}

type systemInfo struct {
	wProcessorArchitecture      uint16
	wReserved                   uint16
	dwPageSize                  uint32
	lpMinimumApplicationAddress uintptr
	lpMaximumApplicationAddress uintptr
	dwActiveProcessorMask       uintptr
	dwNumberOfProcessors        uint32
	dwProcessorType             uint32
	dwAllocationGranularity     uint32
	wProcessorLevel             uint16
	wProcessorRevision          uint16
}

type systemTime struct {
	wYear         uint16
	wMonth        uint16
	wDayOfWeek    uint16
	wDay          uint16
	wHour         uint16
	wMinute       uint16
	wSecond       uint16
	wMilliseconds uint16
}

type timeZoneInfo struct {
	Bias         int32
	StandardName [32]uint16
	StandardDate systemTime
	StandardBias int32
	DaylightName [32]uint16
	DaylightDate systemTime
	DaylightBias int32
}

type msAcpi_ThermalZoneTemperature struct {
	Active             bool
	CriticalTripPoint  uint32
	CurrentTemperature uint32
	InstanceName       string
}

func HostIDWithContext(ctx context.Context) (string, error) {
	// there has been reports of issues on 32bit using golang.org/x/sys/windows/registry, see https://github.com/shirou/gopsutil/pull/312#issuecomment-277422612
	// for rationale of using windows.RegOpenKeyEx/RegQueryValueEx instead of registry.OpenKey/GetStringValue
	var h windows.Handle
	err := windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, windows.StringToUTF16Ptr(`SOFTWARE\Microsoft\Cryptography`), 0, windows.KEY_READ|windows.KEY_WOW64_64KEY, &h)
	if err != nil {
		return "", err
	}
	defer windows.RegCloseKey(h)

	const windowsRegBufLen = 74 // len(`{`) + len(`abcdefgh-1234-456789012-123345456671` * 2) + len(`}`) // 2 == bytes/UTF16
	const uuidLen = 36

	var regBuf [windowsRegBufLen]uint16
	bufLen := uint32(windowsRegBufLen)
	var valType uint32
	err = windows.RegQueryValueEx(h, windows.StringToUTF16Ptr(`MachineGuid`), nil, &valType, (*byte)(unsafe.Pointer(&regBuf[0])), &bufLen)
	if err != nil {
		return "", err
	}

	hostID := windows.UTF16ToString(regBuf[:])
	hostIDLen := len(hostID)
	if hostIDLen != uuidLen {
		return "", fmt.Errorf("HostID incorrect: %q\n", hostID)
	}

	return strings.ToLower(hostID), nil
}

func numProcs(ctx context.Context) (uint64, error) {
	procs, err := process.PidsWithContext(ctx)
	if err != nil {
		return 0, err
	}
	return uint64(len(procs)), nil
}

func readFromRegistry(key windows.Handle, path, name string) (string, error) {
	var err error
	var result string
	var h windows.Handle // like HostIDWithContext(), we query the registry using the raw windows.RegOpenKeyEx/RegQueryValueEx
	err = windows.RegOpenKeyEx(key, windows.StringToUTF16Ptr(path), 0, windows.KEY_READ|windows.KEY_WOW64_64KEY, &h)
	if err != nil {
		return result, err
	}
	defer windows.RegCloseKey(h)
	var bufLen uint32
	var valType uint32
	err = windows.RegQueryValueEx(h, windows.StringToUTF16Ptr(name), nil, &valType, nil, &bufLen)
	if err != nil {
		return result, err
	}

	switch valType {
	case registry.SZ, registry.EXPAND_SZ:
		regBuf := make([]uint16, bufLen/2+1)
		err = windows.RegQueryValueEx(h, windows.StringToUTF16Ptr(name), nil, &valType, (*byte)(unsafe.Pointer(&regBuf[0])), &bufLen)
		if err != nil {
			return result, err
		}
		result = windows.UTF16ToString(regBuf[:])
	case registry.MULTI_SZ:
		regBuf := make([]uint16, bufLen/2+1)
		err = windows.RegQueryValueEx(h, windows.StringToUTF16Ptr(name), nil, &valType, (*byte)(unsafe.Pointer(&regBuf[0])), &bufLen)
		if err != nil {
			return result, err
		}
		result = string(utf16.Decode(regBuf[:]))
	case registry.BINARY:
		regBuf := make([]uint16, bufLen)
		err = windows.RegQueryValueEx(h, windows.StringToUTF16Ptr(name), nil, &valType, (*byte)(unsafe.Pointer(&regBuf[0])), &bufLen)
		if err != nil {
			return result, err
		}
		fmt.Printf("%x", regBuf[:])
		result = string(utf16.Decode(regBuf[:]))
	case registry.DWORD:
		regBuf := make([]byte, 8)
		err = windows.RegQueryValueEx(h, windows.StringToUTF16Ptr(name), nil, &valType, (*byte)(unsafe.Pointer(&regBuf[0])), &bufLen)
		if err != nil {
			return result, err
		}
		var val32 uint32
		copy((*[4]byte)(unsafe.Pointer(&val32))[:], regBuf)
		result = time.Unix(int64(val32), 0).String()
	case registry.QWORD:
		regBuf := make([]byte, 8)
		err = windows.RegQueryValueEx(h, windows.StringToUTF16Ptr(name), nil, &valType, (*byte)(unsafe.Pointer(&regBuf[0])), &bufLen)
		if err != nil {
			return result, err
		}
		var val32 uint64
		copy((*[4]byte)(unsafe.Pointer(&val32))[:], regBuf)
		result = time.Unix(int64(val32), 0).String()
	}
	return result, err
}

func RegisterInfoWithContext(ctx context.Context) (string, string, error) {
	var err error
	var owner, organization string
	// RegisteredOwner
	owner, err = readFromRegistry(windows.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, `RegisteredOwner`)
	if err != nil {
		return owner, organization, err
	}
	// RegisteredOrganization
	organization, err = readFromRegistry(windows.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, `RegisteredOrganization`)
	if err != nil {
		return owner, organization, err
	}
	return owner, organization, err
}

func OSBuildTypeWithContext(ctx context.Context) (string, error) {
	var err error
	var osType string
	// CurrentType
	osType, err = readFromRegistry(windows.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, `CurrentType`)
	if err != nil {
		return osType, err
	}
	return osType, err
}

func ProductIDWithContext(ctx context.Context) (string, error) {
	var err error
	var productID string
	// ProductID
	productID, err = readFromRegistry(windows.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, `ProductID`)
	if err != nil {
		return productID, err
	}
	return productID, err
}

func OSInstallDateTimeWithContext(ctx context.Context) (string, error) {
	var err error
	var installDate string
	// InstallDate
	installDate, err = readFromRegistry(windows.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, `InstallDate`)
	if err != nil {
		return "", err
	}
	return installDate, err
}

func SystemManufactureWithContext(ctx context.Context) (string, string, string, error) {
	var err error
	var manufacture, model, _type string

	// Find SMBIOS data in operating system-specific location.
	rc, _, err := smbios.Stream()
	if err != nil {
		return manufacture, model, _type, err
	}
	// Be sure to close the stream!
	defer rc.Close()

	// Decode SMBIOS structures from the stream.
	d := smbios.NewDecoder(rc)
	ss, err := d.Decode()
	if err != nil {
		return manufacture, model, _type, err
	}

	// Determine SMBIOS version and table location from entry point.
	//major, minor, rev := ep.Version()
	//addr, size := ep.Table()
	//
	//fmt.Printf("SMBIOS %d.%d.%d - table: address: %#x, size: %d\n",
	//	major, minor, rev, addr, size)

	for _, v := range ss {
		if v.Header.Type == 1 && len(v.Strings) > 3 {
			manufacture = v.Strings[0]
			model = v.Strings[1]
			_type = v.Strings[2]
		}
	}

	return manufacture, model, _type, err
}

func BIOSVersionWithContext(ctx context.Context) (string, error) {
	var err error
	var version string
	// Find SMBIOS data in operating system-specific location.
	rc, _, err := smbios.Stream()
	if err != nil {
		return version, err
	}
	// Be sure to close the stream!
	defer rc.Close()

	// Decode SMBIOS structures from the stream.
	d := smbios.NewDecoder(rc)
	ss, err := d.Decode()
	if err != nil {
		return version, err
	}

	// Determine SMBIOS version and table location from entry point.
	//major, minor, rev := ep.Version()
	//addr, size := ep.Table()
	//
	//fmt.Printf("SMBIOS %d.%d.%d - table: address: %#x, size: %d\n",
	//	major, minor, rev, addr, size)

	for _, v := range ss {
		if v.Header.Type == 0 && len(v.Strings) == 3 {
			version = fmt.Sprintf("%v %v %v", v.Strings[0], v.Strings[1], v.Strings[2])
		}
	}

	return version, err
}

func SystemDirectoryWithContext(ctx context.Context) (string, string, error) {
	var err error
	var windowsDir, systemDir string
	windowsDir, err = windows.GetWindowsDirectory()
	if err != nil {
		return windowsDir, systemDir, err
	}
	systemDir, err = windows.GetSystemDirectory()
	if err != nil {
		return windowsDir, systemDir, err
	}
	return windowsDir, systemDir, err
}

func BootDeviceWithContext(ctx context.Context) (string, error) {
	var err error
	var bootDevice string
	bootDevice, err = readFromRegistry(windows.HKEY_LOCAL_MACHINE, `SYSTEM\Setup`, `SystemPartition`)
	if err != nil {
		return bootDevice, err
	}
	return bootDevice, err
}

func InstalledAppListWithContext(ctx context.Context) ([]*AppInfo, error) {
	var err error
	var appList []*AppInfo
	path := `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	params, err := k.ReadSubKeyNames(0)
	if err != nil {
		return nil, err
	}

	for _, param := range params {
		displayName, err := readFromRegistry(windows.HKEY_LOCAL_MACHINE, path+"\\"+param, "DisplayName")
		if err != nil {
			continue
		}
		displayVersion, _ := readFromRegistry(windows.HKEY_LOCAL_MACHINE, path+"\\"+param, "DisplayVersion")
		installDate, _ := readFromRegistry(windows.HKEY_LOCAL_MACHINE, path+"\\"+param, "InstallDate")
		installSource, _ := readFromRegistry(windows.HKEY_LOCAL_MACHINE, path+"\\"+param, "InstallSource")
		installLocation, _ := readFromRegistry(windows.HKEY_LOCAL_MACHINE, path+"\\"+param, "InstallLocation")
		publisher, _ := readFromRegistry(windows.HKEY_LOCAL_MACHINE, path+"\\"+param, "Publisher")
		appList = append(appList, &AppInfo{
			Name:            displayName,
			Version:         displayVersion,
			InstallDate:     installDate,
			InstallSource:   installSource,
			InstallLocation: installLocation,
			Publisher:       publisher,
		})
	}

	return appList, err
}

func SystemLocaleWithContext(ctx context.Context) (string, error) {
	var err error
	var systemLocale string
	var buffer [1024]uint16

	_, _, _ = procGetLocaleInfo.Call(uintptr(2048), uintptr(0x00000001), uintptr(unsafe.Pointer(&buffer[0])), uintptr(1024))
	langID := windows.UTF16ToString(buffer[:])
	systemLocale, _ = translateRFC1766(langID)

	return systemLocale, err
}

func InputLocaleWithContext(ctx context.Context) (string, error) {
	var err error
	var inputLocale string
	var HKL uintptr

	HKL, _, _ = procGetKeyboardLayout.Call(uintptr(0))
	langID := fmt.Sprintf("%04X", HKL&0x0000FFFF)
	inputLocale, _ = translateRFC1766(langID)

	return inputLocale, err
}

func translateRFC1766(langID string) (string, error) {
	path := `MIME\\Database\\Rfc1766`
	code, err := readFromRegistry(windows.HKEY_CLASSES_ROOT, path, langID)
	if err != nil {
		return "", err
	}
	pos := strings.Index(code, ";")
	if pos == -1 {
		return "", fmt.Errorf("parse %s result error", path)
	}
	tmp := windows.StringToUTF16(code[pos:])
	procSHLoadIndirectString.Call(
		uintptr(unsafe.Pointer(&tmp[1])),
		uintptr(unsafe.Pointer(&tmp[1])),
		uintptr(1024-pos-1),
		uintptr(0))

	return code[:pos] + windows.UTF16ToString(tmp[:]), nil
}

func TimeZoneWithContext(ctx context.Context) (string, error) {
	var err error
	var timezone string
	path := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones`

	var timeZoneInfo timeZoneInfo
	procGetTimeZoneInformation.Call(uintptr(unsafe.Pointer(&timeZoneInfo)))
	standardName := windows.UTF16ToString(timeZoneInfo.StandardName[:])

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return timezone, err
	}
	defer k.Close()

	params, err := k.ReadSubKeyNames(0)
	if err != nil {
		return timezone, err
	}

	for _, v := range params {
		if v != standardName {
			continue
		}
		timezone, err = readFromRegistry(windows.HKEY_LOCAL_MACHINE, path+"\\"+v, "Display")
		break
	}
	return timezone, err
}

func PageFileLocationWithContext(ctx context.Context) (string, error) {
	var err error
	var location string
	location, err = readFromRegistry(windows.HKEY_LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`, `ExistingPageFiles`)
	if err != nil {
		return location, err
	}
	return location, err
}

func DomainWithContext(ctx context.Context) (string, error) {
	var err error
	var domain string
	var netJoinStatus uint32
	var p *[1 << 10]uint16

	errno, _, _ := procNetGetJoinInformation.Call(0, uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&netJoinStatus)))
	if errno != 0 {
		return domain, syscall.Errno(errno)
	}
	defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(p)))
	domain = syscall.UTF16ToString(p[:])

	return domain, err
}

func LogonServerWithContext(ctx context.Context) (string, error) {
	var err error
	var logon string
	logon, _ = os.LookupEnv("LOGONSERVER")
	return logon, err
}

func HotFixListWithContext(ctx context.Context) ([]string, error) {
	var err error
	var appList []*AppInfo
	var hotFix []string
	appList, err = InstalledAppListWithContext(ctx)
	for _, v := range appList {
		if !strings.Contains(v.Name, "KB") {
			continue
		}
		hotFix = append(hotFix, v.Name)

	}
	return hotFix, err
}

func OSUUIDWithContext(ctx context.Context) (string, error) {
	return machineid.ID()
}

func UptimeWithContext(ctx context.Context) (uint64, error) {
	procGetTickCount := procGetTickCount64
	err := procGetTickCount64.Find()
	if err != nil {
		procGetTickCount = procGetTickCount32 // handle WinXP, but keep in mind that "the time will wrap around to zero if the system is run continuously for 49.7 days." from MSDN
	}
	r1, _, lastErr := syscall.Syscall(procGetTickCount.Addr(), 0, 0, 0, 0)
	if lastErr != 0 {
		return 0, lastErr
	}
	return uint64((time.Duration(r1) * time.Millisecond).Seconds()), nil
}

// cachedBootTime must be accessed via atomic.Load/StoreUint64
var cachedBootTime uint64

func BootTimeWithContext(ctx context.Context) (uint64, error) {
	t := atomic.LoadUint64(&cachedBootTime)
	if t != 0 {
		return t, nil
	}
	up, err := Uptime()
	if err != nil {
		return 0, err
	}
	t = timeSince(up)
	atomic.StoreUint64(&cachedBootTime, t)
	return t, nil
}

func PlatformInformationWithContext(ctx context.Context) (platform string, family string, version string, err error) {
	// GetVersionEx lies on Windows 8.1 and returns as Windows 8 if we don't declare compatibility in manifest
	// RtlGetVersion bypasses this lying layer and returns the true Windows version
	// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-rtlgetversion
	// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ns-wdm-_osversioninfoexw
	var osInfo osVersionInfoExW
	osInfo.dwOSVersionInfoSize = uint32(unsafe.Sizeof(osInfo))
	ret, _, err := procRtlGetVersion.Call(uintptr(unsafe.Pointer(&osInfo)))
	if ret != 0 {
		return
	}

	// Platform
	var h windows.Handle // like HostIDWithContext(), we query the registry using the raw windows.RegOpenKeyEx/RegQueryValueEx
	err = windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, windows.StringToUTF16Ptr(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`), 0, windows.KEY_READ|windows.KEY_WOW64_64KEY, &h)
	if err != nil {
		return
	}
	defer windows.RegCloseKey(h)
	var bufLen uint32
	var valType uint32
	err = windows.RegQueryValueEx(h, windows.StringToUTF16Ptr(`ProductName`), nil, &valType, nil, &bufLen)
	if err != nil {
		return
	}
	regBuf := make([]uint16, bufLen/2+1)
	err = windows.RegQueryValueEx(h, windows.StringToUTF16Ptr(`ProductName`), nil, &valType, (*byte)(unsafe.Pointer(&regBuf[0])), &bufLen)
	if err != nil {
		return
	}
	platform = windows.UTF16ToString(regBuf[:])
	if !strings.HasPrefix(platform, "Microsoft") {
		platform = "Microsoft " + platform
	}
	err = windows.RegQueryValueEx(h, windows.StringToUTF16Ptr(`CSDVersion`), nil, &valType, nil, &bufLen) // append Service Pack number, only on success
	if err == nil {                                                                                       // don't return an error if only the Service Pack retrieval fails
		regBuf = make([]uint16, bufLen/2+1)
		err = windows.RegQueryValueEx(h, windows.StringToUTF16Ptr(`CSDVersion`), nil, &valType, (*byte)(unsafe.Pointer(&regBuf[0])), &bufLen)
		if err == nil {
			platform += " " + windows.UTF16ToString(regBuf[:])
		}
	}

	// PlatformFamily
	switch osInfo.wProductType {
	case 1:
		family = "Standalone Workstation"
	case 2:
		family = "Server (Domain Controller)"
	case 3:
		family = "Server"
	}

	// Platform Version
	version = fmt.Sprintf("%d.%d.%d Build %d", osInfo.dwMajorVersion, osInfo.dwMinorVersion, osInfo.dwBuildNumber, osInfo.dwBuildNumber)

	return platform, family, version, nil
}

func UsersWithContext(ctx context.Context) ([]UserStat, error) {
	var ret []UserStat

	return ret, common.ErrNotImplementedError
}

func SensorsTemperaturesWithContext(ctx context.Context) ([]TemperatureStat, error) {
	var ret []TemperatureStat
	var dst []msAcpi_ThermalZoneTemperature
	q := wmi.CreateQuery(&dst, "")
	if err := common.WMIQueryWithContext(ctx, q, &dst, nil, "root/wmi"); err != nil {
		return ret, err
	}

	for _, v := range dst {
		ts := TemperatureStat{
			SensorKey:   v.InstanceName,
			Temperature: kelvinToCelsius(v.CurrentTemperature, 2),
		}
		ret = append(ret, ts)
	}

	return ret, nil
}

func kelvinToCelsius(temp uint32, n int) float64 {
	// wmi return temperature Kelvin * 10, so need to divide the result by 10,
	// and then minus 273.15 to get °Celsius.
	t := float64(temp/10) - 273.15
	n10 := math.Pow10(n)
	return math.Trunc((t+0.5/n10)*n10) / n10
}

func VirtualizationWithContext(ctx context.Context) (string, string, error) {
	return "", "", common.ErrNotImplementedError
}

func KernelVersionWithContext(ctx context.Context) (string, error) {
	_, _, version, err := PlatformInformationWithContext(ctx)
	return version, err
}

func KernelArch() (string, error) {
	var systemInfo systemInfo
	procGetNativeSystemInfo.Call(uintptr(unsafe.Pointer(&systemInfo)))

	const (
		PROCESSOR_ARCHITECTURE_INTEL = 0
		PROCESSOR_ARCHITECTURE_ARM   = 5
		PROCESSOR_ARCHITECTURE_ARM64 = 12
		PROCESSOR_ARCHITECTURE_IA64  = 6
		PROCESSOR_ARCHITECTURE_AMD64 = 9
	)
	switch systemInfo.wProcessorArchitecture {
	case PROCESSOR_ARCHITECTURE_INTEL:
		if systemInfo.wProcessorLevel < 3 {
			return "i386", nil
		}
		if systemInfo.wProcessorLevel > 6 {
			return "i686", nil
		}
		return fmt.Sprintf("i%d86", systemInfo.wProcessorLevel), nil
	case PROCESSOR_ARCHITECTURE_ARM:
		return "arm", nil
	case PROCESSOR_ARCHITECTURE_ARM64:
		return "aarch64", nil
	case PROCESSOR_ARCHITECTURE_IA64:
		return "ia64", nil
	case PROCESSOR_ARCHITECTURE_AMD64:
		return "x86_64", nil
	}
	return "", nil
}
