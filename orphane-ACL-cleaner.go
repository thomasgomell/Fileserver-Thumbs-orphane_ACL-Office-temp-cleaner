package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows API constants and structures
const (
	SECURITY_DESCRIPTOR_REVISION = 1
	ACL_REVISION                 = 2
	SE_FILE_OBJECT               = 1
	DACL_SECURITY_INFORMATION    = 0x00000004
)

// ACE header structure
type ACE_HEADER struct {
	AceType  byte
	AceFlags byte
	AceSize  uint16
}

// ACE structure
type ACE struct {
	Header   ACE_HEADER
	Mask     uint32
	SidStart uintptr
}

type ACL_SIZE_INFORMATION struct {
	AceCount      uint32
	AclBytesInUse uint32
	AclBytesFree  uint32
}

// Windows API functions
var (
	advapi32                  = windows.NewLazySystemDLL("advapi32.dll")
	getNamedSecurityInfo      = advapi32.NewProc("GetNamedSecurityInfoW")
	setNamedSecurityInfo      = advapi32.NewProc("SetNamedSecurityInfoW")
	getSecurityDescriptorDacl = advapi32.NewProc("GetSecurityDescriptorDacl")
	getAclInformation         = advapi32.NewProc("GetAclInformation")
	getAce                    = advapi32.NewProc("GetAce")
	initializeAcl             = advapi32.NewProc("InitializeAcl")
	addAce                    = advapi32.NewProc("AddAce")
)

func main() {
	rootPath := flag.String("path", ".", "Root path to start scanning")
	interactive := flag.Bool("i", false, "Interactive mode")
	flag.Parse()

	if *interactive {
		fmt.Print("Enter root path (default '.'): ")
		var input string
		fmt.Scanln(&input)
		if input != "" {
			*rootPath = input
		}
	}

	if _, err := os.Stat(*rootPath); os.IsNotExist(err) {
		fmt.Printf("Error: Path %s does not exist\n", *rootPath)
		return
	}

	logFileName := fmt.Sprintf("acl_cleanup_%s.csv", time.Now().Format("20060102_150405"))
	logFile, err := os.Create(logFileName)
	if err != nil {
		fmt.Printf("Error creating log file: %v\n", err)
		return
	}
	defer logFile.Close()

	writer := csv.NewWriter(logFile)
	defer writer.Flush()
	writer.Write([]string{"Action", "Path", "Details"})

	cleanOrphanedACLs(*rootPath, writer)
}

func cleanOrphanedACLs(rootPath string, logFile *csv.Writer) {
	var processedFiles, cleanedFiles int

	// Add error codes mapping
	errorCodes := map[uint32]string{
		5:    "ERROR_ACCESS_DENIED - Zugriff verweigert",
		1332: "ERROR_NONE_MAPPED - Keine SID/Name-Zuordnung verfügbar",
		1307: "ERROR_INVALID_OWNER - Ungültiger Besitzer",
		1336: "ERROR_INVALID_ACL - Ungültige ACL-Struktur",
		1340: "ERROR_INVALID_SECURITY_DESCR - Ungültiger Security Descriptor",
	}

	filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logFile.Write([]string{"ERROR", path, fmt.Sprintf("Scan-Fehler: %v", err)})
			if os.IsPermission(err) {
				fmt.Printf("Keine Berechtigung für: %s\n", path)
				return filepath.SkipDir
			}
			return nil
		}

		processedFiles++
		fmt.Printf("Verarbeite: %s\n", path)

		// Get security descriptor
		var pSD uintptr
		pathPtr, err := syscall.UTF16PtrFromString(path)
		if err != nil {
			logFile.Write([]string{"ERROR", path, fmt.Sprintf("Pfad-Konvertierung fehlgeschlagen: %v", err)})
			return nil
		}

		ret, _, errNo := getNamedSecurityInfo.Call(
			uintptr(unsafe.Pointer(pathPtr)),
			uintptr(SE_FILE_OBJECT),
			uintptr(DACL_SECURITY_INFORMATION),
			0,
			0,
			uintptr(unsafe.Pointer(&pSD)),
			0,
			0)
		if ret != 0 {
			errno := syscall.Errno(ret)
			errorMsg := fmt.Sprintf("Security-Info-Fehler: %v", errno)
			if msg, ok := errorCodes[uint32(errno)]; ok {
				errorMsg = fmt.Sprintf("%s (%s)", errorMsg, msg)
			}
			logFile.Write([]string{"ERROR", path, errorMsg})
			fmt.Printf("Fehler bei %s: %s\n", path, errorMsg)
			if uint32(errno) == 5 { // ACCESS_DENIED
				return filepath.SkipDir
			}
			return nil
		}

		// Fix LocalFree error handling
		if pSD != 0 {
			handle := windows.Handle(pSD)
			if handle != 0 {
				// Properly handle both return values from LocalFree
				if _, err := windows.LocalFree(handle); err != nil {
					logFile.Write([]string{"ERROR", path, fmt.Sprintf("Speicherfreigabe fehlgeschlagen: %v", err)})
				}
			}
		}

		// Get DACL
		var dacl *windows.ACL
		var present bool
		var defaulted bool
		ret, _, errNo = getSecurityDescriptorDacl.Call(
			pSD,
			uintptr(unsafe.Pointer(&present)),
			uintptr(unsafe.Pointer(&dacl)),
			uintptr(unsafe.Pointer(&defaulted)))
		if ret == 0 || !present {
			logFile.Write([]string{"ERROR", path, "DACL-Fehler"})
			return nil
		}

		// Get ACL information
		var aclInfo ACL_SIZE_INFORMATION
		ret, _, errNo = getAclInformation.Call(
			uintptr(unsafe.Pointer(dacl)),
			uintptr(unsafe.Pointer(&aclInfo)),
			uintptr(unsafe.Sizeof(aclInfo)),
			2) // AclSizeInformation
		if ret == 0 {
			if errNo, ok := errNo.(syscall.Errno); ok {
				logFile.Write([]string{"ERROR", path, fmt.Sprintf("ACL-Info-Fehler: %v", errNo)})
			}
			return nil
		}

		var validACEs []ACE
		for i := uint32(0); i < aclInfo.AceCount; i++ {
			var acePtr *ACE
			ret, _, errNo = getAce.Call(
				uintptr(unsafe.Pointer(dacl)),
				uintptr(i),
				uintptr(unsafe.Pointer(&acePtr)))
			if ret == 0 {
				if errNo, ok := errNo.(syscall.Errno); ok {
					errorMsg := fmt.Sprintf("ACE-Fehler: %v", errNo)
					if msg, ok := errorCodes[uint32(errNo)]; ok {
						errorMsg = fmt.Sprintf("%s (%s)", errorMsg, msg)
					}
					logFile.Write([]string{"ERROR", path, errorMsg})
					fmt.Printf("ACE-Fehler bei %s: %s\n", path, errorMsg)
				}
				continue
			}

			// Enhanced SID validation
			sid := (*windows.SID)(unsafe.Pointer(acePtr.SidStart))
			_, _, _, err = sid.LookupAccount("")
			if err == nil {
				validACEs = append(validACEs, *acePtr)
			} else {
				sidString := sid.String()
				logFile.Write([]string{"INFO", path,
					fmt.Sprintf("Verwaiste SID entfernt: %s (%v)", sidString, err)})
				fmt.Printf("Verwaiste SID gefunden in %s: %s\n", path, sidString)
				cleanedFiles++
			}
		}

		// Create new ACL if needed
		if len(validACEs) < int(aclInfo.AceCount) {
			newAclSize := uint32(unsafe.Sizeof(windows.ACL{}))
			for _, ace := range validACEs {
				newAclSize += uint32(ace.Header.AceSize)
			}

			newDacl := make([]byte, newAclSize)
			ret, _, errNo = initializeAcl.Call(
				uintptr(unsafe.Pointer(&newDacl[0])),
				uintptr(newAclSize),
				uintptr(ACL_REVISION))
			if ret == 0 {
				if errNo, ok := errNo.(syscall.Errno); ok {
					logFile.Write([]string{"ERROR", path, fmt.Sprintf("Neue ACL-Fehler: %v", errNo)})
				}
				return nil
			}

			ret, _, errNo = setNamedSecurityInfo.Call(
				uintptr(unsafe.Pointer(pathPtr)),
				uintptr(SE_FILE_OBJECT),
				uintptr(DACL_SECURITY_INFORMATION),
				0,
				0,
				uintptr(unsafe.Pointer(&newDacl[0])),
				0)
			if ret != 0 {
				errno := syscall.Errno(ret)
				errorMsg := fmt.Sprintf("ACL-Update-Fehler: %v", errno)
				if msg, ok := errorCodes[uint32(errno)]; ok {
					errorMsg = fmt.Sprintf("%s (%s)", errorMsg, msg)
				}
				logFile.Write([]string{"ERROR", path, errorMsg})
				fmt.Printf("Update-Fehler bei %s: %s\n", path, errorMsg)
			} else {
				msg := fmt.Sprintf("ACLs bereinigt: %d entfernt",
					int(aclInfo.AceCount)-len(validACEs))
				logFile.Write([]string{"UPDATED", path, msg})
				fmt.Printf("Erfolgreich aktualisiert: %s - %s\n", path, msg)
			}
		}

		return nil
	})

	// Write summary
	summary := fmt.Sprintf("Verarbeitet: %d, Bereinigt: %d", processedFiles, cleanedFiles)
	logFile.Write([]string{"SUMMARY", rootPath, summary})
	fmt.Printf("\nZusammenfassung:\n%s\n", summary)
}
