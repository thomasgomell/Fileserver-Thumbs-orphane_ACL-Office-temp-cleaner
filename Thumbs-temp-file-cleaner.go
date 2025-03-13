package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
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

	logFileName := fmt.Sprintf("tempfiles_cleanup_%s.csv", time.Now().Format("20060102_150405"))
	logFile, err := os.Create(logFileName)
	if err != nil {
		fmt.Printf("Error creating log file: %v\n", err)
		return
	}
	defer logFile.Close()

	writer := csv.NewWriter(logFile)
	defer writer.Flush()
	writer.Write([]string{"Action", "Path", "Details"})

	cleanupTempFiles(*rootPath, writer)
}

func cleanupTempFiles(rootPath string, logFile *csv.Writer) {
	var scannedFiles, deletedFiles int

	patterns := []string{
		"thumbs.db",
		"~$*.docx",
		"~$*.doc",
		"~$*.xlsx",
		"~$*.xls",
		"~$*.pptx",
		"~$*.ppt",
		"~*.tmp",
	}

	filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logFile.Write([]string{"ERROR", path, fmt.Sprintf("Scan-Fehler: %v", err)})
			return nil
		}

		if !info.IsDir() {
			scannedFiles++
			fileName := strings.ToLower(info.Name())

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

	logFile.Write([]string{"SUMMARY", rootPath,
		fmt.Sprintf("Überprüft: %d, Gelöscht: %d", scannedFiles, deletedFiles)})
}
