package main

import (
    "encoding/csv"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"

    "github.com/hectane/go-acl"
    "golang.org/x/sys/windows"
)

// cleanupUnwantedFiles entfernt unerwünschte Dateien wie Thumbs.db und temporäre Dateien
func cleanupUnwantedFiles(rootPath string, logFile *csv.Writer, wg *sync.WaitGroup) {
    defer wg.Done()
    var scannedFiles, deletedFiles int

    filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            logFile.Write([]string{"ERROR", path, fmt.Sprintf("Scan-Fehler: %v", err)})
            return nil
        }

        if !info.IsDir() {
            scannedFiles++
            fileName := strings.ToLower(info.Name())

            // Muster für unerwünschte Dateien
            patterns := []string{"thumbs.db", "~$*.docx", "~$*.doc", "~$*.xlsx", "~$*.xls", "~$*.pptx", "~$*.ppt", "~*.tmp"}
            for _, pattern := range patterns {
                match, _ := filepath.Match(pattern, fileName)
                if match {
                    if err := os.Remove(path); err == nil {
                        logFile.Write([]string{"DELETE", path, time.Now().Format(time.RFC3339)})
                        deletedFiles++
                    } else {
                        logFile.Write([]string{"ERROR", path, fmt.Sprintf("Löschfehler: %v", err)})
                    }
                    break
                }
            }
        }
        return nil
    })

    logFile.Write([]string{"SUMMARY", rootPath, fmt.Sprintf("Überprüft: %d, Gelöscht: %d", scannedFiles, deletedFiles)})
}

// removeOrphanedACLs entfernt verwaiste ACEs aus den ACLs
func removeOrphanedACLs(rootPath string, logFile *csv.Writer, wg *sync.WaitGroup) {
    defer wg.Done()

    filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            logFile.Write([]string{"ERROR", path, fmt.Sprintf("Scan-Fehler: %v", err)})
            return nil
        }

        // Aktuelle ACL-Einträge abrufen
        entries, err := acl.GetEntries(path)
        if err != nil {
            logFile.Write([]string{"ERROR", path, fmt.Sprintf("Fehler beim Abrufen der ACL: %v", err)})
            return nil
        }

        var validEntries []acl.Entry
        for _, entry := range entries {
            sid, err := windows.StringToSid(entry.Trustee)
            if err != nil {
                logFile.Write([]string{"INFO", path, fmt.Sprintf("Ungültige SID gefunden und übersprungen: %s", entry.Trustee)})
                continue
            }

            _, _, _, err = sid.LookupAccount("")
            if err != nil {
                logFile.Write([]string{"INFO", path, fmt.Sprintf("Verwaiste SID entfernt: %s", entry.Trustee)})
                continue
            }

            validEntries = append(validEntries, entry)
        }

        // Neue ACL anwenden
        if err := acl.Apply(path, true, false, validEntries...); err != nil {
            logFile.Write([]string{"ERROR", path, fmt.Sprintf("Fehler beim Anwenden der neuen ACL: %v", err)})
        }

        return nil
    })
}

// replaceOrphanedOwners ersetzt verwaiste NTFS-Besitzer durch einen gültigen Benutzer
func replaceOrphanedOwners(rootPath string, newOwnerSID *windows.SID, logFile *csv.Writer, wg *sync.WaitGroup) {
    defer wg.Done()

    filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            logFile.Write([]string{"ERROR", path, fmt.Sprintf("Scan-Fehler: %v", err)})
            return nil
        }

        // Sicherheitsinformationen abrufen
        var sd *windows.SECURITY_DESCRIPTOR
        err = windows.GetNamedSecurityInfo(
            path,
            windows.SE_FILE_OBJECT,
            windows.OWNER_SECURITY_INFORMATION,
            nil,
            nil,
            nil,
            nil,
            &sd,
        )
        if err != nil {
            logFile.Write([]string{"ERROR", path, fmt.Sprintf("Fehler beim Abrufen der Sicherheitsinformationen: %v", err)})
            return nil
        }

        // Besitzer-SID abrufen
        owner, _, err := sd.Owner()
        if err != nil {
            logFile.Write([]string{"ERROR", path, fmt.Sprintf("Fehler beim Abrufen des Besitzers: %v", err)})
            return nil
        }

        // Überprüfen, ob die SID aufgelöst werden kann
        _, _, _, err = owner.LookupAccount("")
        if err != nil {
            // Besitzer ist verwaist, neuen Besitzer setzen
            err = windows.SetNamedSecurityInfo(
                path,
                windows.SE_FILE_OBJECT,
                windows.OWNER_SECURITY_INFORMATION,
                newOwnerSID,
                nil,
                nil,
                nil,
            )
            if err != nil {
                logFile.Write([]string{"ERROR", path, fmt.Sprintf("Fehler beim Setzen des neuen Besitzers: %v", err)})
            } else {
                logFile.Write([]string{"OWNER_CHANGED", path, fmt.Sprintf("Neuer Besitzer gesetzt: %v", newOwnerSID)})
           