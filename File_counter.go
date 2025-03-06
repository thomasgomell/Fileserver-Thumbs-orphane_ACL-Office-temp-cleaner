package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Funktion zum Zählen der Dateien in einem Verzeichnis mit paralleler Verarbeitung
func countFiles(root string) int {
	var count int
	var wg sync.WaitGroup
	fileChan := make(chan string, 100) // Buffered Channel für parallele Verarbeitung

	// Worker-Goroutine für das Zählen
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range fileChan {
			count++
		}
	}()

	// Startzeit messen
	startTime := time.Now()

	// Walk-Funktion zum parallelen Durchsuchen des Verzeichnisses
	wg.Add(1)
	go func() {
		defer wg.Done()
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				fileChan <- path
			}
			return nil
		})
		close(fileChan)
	}()

	wg.Wait()

	// Endzeit messen
	duration := time.Since(startTime)
	fmt.Printf("Scan abgeschlossen in: %v Sekunden\n", duration.Seconds())

	return count
}

func main() {
	dir := "C:\\" // <-- Verzeichnis anpassen!
	fmt.Printf("Scanne Verzeichnis: %s\n", dir)
	fileCount := countFiles(dir)
	fmt.Printf("Anzahl der Dateien: %d\n", fileCount)
}
