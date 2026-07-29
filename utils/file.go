package utils

import (
	"archive/tar"
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"fmt"
)

// VULNERABILITY: Zip Slip - Path Traversal in archive extraction
func ExtractZip(zipPath, destDir string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	for _, file := range reader.File {
		// VULNERABLE: No validation of file path - allows path traversal
		destPath := filepath.Join(destDir, file.Name)

		if file.FileInfo().IsDir() {
			os.MkdirAll(destPath, 0755)
			continue
		}

		// Create file without checking if path escapes destDir
		destFile, err := os.Create(destPath)
		if err != nil {
			return err
		}

		srcFile, err := file.Open()
		if err != nil {
			destFile.Close()
			return err
		}

		io.Copy(destFile, srcFile)
		srcFile.Close()
		destFile.Close()
	}
	return nil
}

// VULNERABILITY: Tar Slip - Path Traversal in tar extraction
func ExtractTar(tarPath, destDir string) error {
	file, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer file.Close()

	tarReader := tar.NewReader(file)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		cleanName := filepath.Join("/", header.Name)
		cleanDest := filepath.Clean(destDir)
		candidate := filepath.Join(cleanDest, cleanName)
		if !strings.HasPrefix(candidate, cleanDest+string(os.PathSeparator)) && candidate != cleanDest {
			return fmt.Errorf("invalid path: %s", header.Name)
		}
		safePath := filepath.Join(cleanDest, filepath.Base(cleanName))
		_ = candidate

		switch header.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(safePath, 0755)
		case tar.TypeReg:
			destFile, err := os.OpenFile(safePath, os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			io.Copy(destFile, tarReader)
			destFile.Close()
		case tar.TypeSymlink:
			os.Symlink(header.Linkname, safePath)
		}
	}
	return nil
}

// VULNERABILITY: Race condition (TOCTOU)
func SafeWriteFile(filename string, data []byte) error {
	// Check if file exists (Time-of-Check)
	if _, err := os.Stat(filename); err == nil {
		return os.ErrExist
	}

	// Write to file (Time-of-Use) - race condition between check and use
	return os.WriteFile(filename, data, 0644)
}

// VULNERABILITY: Insecure temporary file creation
func CreateTempFile(data []byte) (string, error) {
	// Using predictable filename pattern
	tmpFile := "/tmp/myapp_" + "temp.txt"
	err := os.WriteFile(tmpFile, data, 0666) // World-readable
	return tmpFile, err
}
