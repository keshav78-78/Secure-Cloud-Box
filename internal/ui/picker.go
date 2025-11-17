package ui

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ktr0731/go-fuzzyfinder"
)

// --------- Windows drives list ---------

func listDrives() []string {
	// non-Windows: just root
	if runtime.GOOS != "windows" {
		return []string{"/"}
	}

	var drives []string
	for c := 'C'; c <= 'Z'; c++ {
		path := string(c) + ":\\"
		if _, err := os.Stat(path); err == nil {
			drives = append(drives, path)
		}
	}
	if len(drives) == 0 {
		drives = []string{"C:\\"}
	}
	return drives
}

// --------- File listing (bounded depth) ---------

func ListFiles(root string, maxDepth int) ([]string, error) {
	root = filepath.Clean(root)
	var files []string

	sep := string(os.PathSeparator)
	rootDepth := strings.Count(root, sep)

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// ignore permission etc.
			return nil
		}

		depth := strings.Count(path, sep) - rootDepth
		if depth > maxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if !d.IsDir() {
			files = append(files, path)
		}
		return nil
	})

	return files, err
}

// --------- Two-step picker: drive -> file ---------

// PickFile: ignore root on Windows, just pick drive then file.
func PickFile(root string, maxDepth int) (string, error) {
	drives := listDrives()

	// 1) pick drive
	driveIdx, err := fuzzyfinder.Find(drives, func(i int) string {
		return drives[i]
	})
	if err != nil {
		return "", err
	}
	chosenDrive := drives[driveIdx]

	// 2) list files in that drive
	files, err := ListFiles(chosenDrive, maxDepth)
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		return "", fmt.Errorf("no files found under %s", chosenDrive)
	}

	// 3) pick file
	fileIdx, err := fuzzyfinder.Find(files, func(i int) string {
		return files[i]
	})
	if err != nil {
		return "", err
	}
	return files[fileIdx], nil
}
