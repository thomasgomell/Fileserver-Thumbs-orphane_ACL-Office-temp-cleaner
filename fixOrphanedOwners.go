package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hectane/go-acl"
	"golang.org/x/sys/windows"
)

func main() {
	rootPath := flag.String("path", ".", "Root path to start scanning")
	newOwnerName := flag.String("newowner", "Administrator", "New owner for orphaned files")
	interactive := flag.Bool("i", false, "Interactive mode")
	flag.Parse()

	if *interactive {
		fmt.Print("Enter root path (default '.'): ")
		var input string
		fmt.Scanln(&input)
		if input != "" {
			*rootPath = input
		}

		fmt.Print("Enter new owner name (default 'Administrator'): ")
		fmt.Scanln(&input)
		if input != "" {
			*newOwnerName = input
		}
	}

	if _, err := os.Stat(*rootPath); os.IsNotExist(err) {
		fmt.Printf("Error: Path %s does not exist\n", *rootPath)
		return
	}

	sid, err := getOwnerSID(*newOwnerName)
	if err != nil {
		fmt.Printf("Error getting SID for %s: %v\n", *newOwnerName, err)
		return
	}

	logFileName := fmt.Sprintf("owner_fix_%s.csv", time.Now().Format("20060102_150405"))
	logFile, err := os.Create(logFileName)
	if err != nil {
		fmt.Printf("Error creating log file: %v\n", err)
		return
	}
	defer logFile.Close()

	writer := csv.NewWriter(logFile)
	defer writer.Flush()
	writer.Write([]string{"Action", "Path", "Details"})

	fixOrphanedOwners(*rootPath, sid, writer)
}

func getOwnerSID(username string) (*windows.SID, error) {
	sid, _, _, err := windows.LookupSID("", username)
	if err != nil {
		return nil, fmt.Errorf("error looking up SID for %s: %v", username, err)
	}
	return sid, nil
}

func fixOrphanedOwners(rootPath string, newOwnerSID *windows.SID, logFile *csv.Writer) {
	var processedFiles, changedOwners int

	filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logFile.Write([]string{"ERROR", path, fmt.Sprintf("Scan-Fehler: %v", err)})
			return filepath.SkipDir
		}

		processedFiles++

		sd, err := acl.GetSecurityInfo(path, acl.SE_FILE_OBJECT, acl.OWNER_SECURITY_INFORMATION)
		if err != nil {
			logFile.Write([]string{"ERROR", path, fmt.Sprintf("Owner-Info-Fehler: %v", err)})
			return nil
		}

		ownerSid, err := sd.GetOwner()
		if err != nil {
			logFile.Write([]string{"ERROR", path, fmt.Sprintf("Owner-Abruf-Fehler: %v", err)})
			return nil
		}

		_, _, _, err = ownerSid.LookupAccount("")
		if err != nil {
			err = acl.SetSecurityInfo(path, acl.SE_FILE_OBJECT,
				acl.OWNER_SECURITY_INFORMATION, newOwnerSID, nil, nil, nil)
			if err != nil {
				logFile.Write([]string{"ERROR", path,
					fmt.Sprintf("Owner-Update-Fehler: %v", err)})
			} else {
				changedOwners++
				logFile.Write([]string{"UPDATED", path,
					fmt.Sprintf("Neuer Besitzer gesetzt: %v", newOwnerSID)})
			}
		}

		return nil
	})

	logFile.Write([]string{"SUMMARY", rootPath,
		fmt.Sprintf("Verarbeitet: %d, Geändert: %d", processedFiles, changedOwners)})
}
