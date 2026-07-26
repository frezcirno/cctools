// Package vfs is a tiny filesystem abstraction that transparently falls back to
// an in-memory overlay when the working directory is not writable (e.g. a
// read-only serverless filesystem).
//
// All application code must go through Store/Load/Stat rather than the os
// package directly, so the same code path works on a read-only host and on a
// normal server with disk.
package vfs

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// IsReadOnly reports whether the working directory rejected a probe write at
// startup. When true, Store writes to the in-memory overlay instead of disk.
var IsReadOnly = false

func init() {
	// Test if the filesystem is read-only
	os.Remove(".ct_test_fs")
	_, err := os.OpenFile(".ct_test_fs", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		log.Println("Filesystem is read-only")
		IsReadOnly = true
	}
	os.Remove(".ct_test_fs")
}

func resolvePath(fspath string) string {
	// Convert the relative path to an absolute path
	absPath, err := filepath.Abs(fspath)
	if err != nil {
		// Handle error, for example, log it or return a default value
		log.Println("Error resolving path:", err)
		return fspath
	}
	return absPath
}

// Store writes data to fspath, using the in-memory overlay on a read-only FS.
func Store(fspath string, data []byte) {
	if IsReadOnly {
		memfsStore(fspath, data)
	} else {
		fileStore(fspath, data)
	}
}

// Load reads fspath, checking the in-memory overlay first on a read-only FS.
func Load(fspath string) ([]byte, error) {
	if IsReadOnly {
		// try to load from memory first
		if data, err := memfsLoad(fspath); err == nil {
			return data, nil
		}
	}
	return fileLoad(fspath)
}

// Stat reports metadata for fspath, checking the overlay first on a read-only FS.
func Stat(fspath string) (os.FileInfo, error) {
	if IsReadOnly {
		// try to load from memory first
		if info, err := memfsStat(fspath); err == nil {
			return info, nil
		}
	}
	key := resolvePath(fspath)
	return os.Stat(key)
}

func fileLoad(fspath string) ([]byte, error) {
	key := resolvePath(fspath)
	data, err := os.ReadFile(key)
	if err != nil {
		log.Println("Error reading file from real fs:", err)
		return nil, err
	}
	return data, nil
}

func fileStore(fspath string, data []byte) {
	key := resolvePath(fspath)
	err := os.WriteFile(key, data, 0644)
	if err != nil {
		log.Println("Error writing file to real fs:", err)
	}
}

type memFile struct {
	data    []byte
	modtime time.Time
}

type memFileInfo struct {
	name    string
	size    int64
	modtime time.Time
}

func (fi *memFileInfo) Name() string {
	return filepath.Base(fi.name)
}

func (fi *memFileInfo) Size() int64 {
	return fi.size
}

func (fi *memFileInfo) Mode() os.FileMode {
	return 0644
}

func (fi *memFileInfo) ModTime() time.Time {
	return fi.modtime
}

func (fi *memFileInfo) IsDir() bool {
	return false
}

func (fi *memFileInfo) Sys() any {
	return nil
}

var (
	overlayMu sync.RWMutex
	overlay   = map[string]memFile{}
)

func memfsStore(fspath string, data []byte) {
	pathKey := resolvePath(fspath)
	overlayMu.Lock()
	overlay[pathKey] = memFile{data, time.Now()}
	overlayMu.Unlock()
}

func memfsLoad(fspath string) ([]byte, error) {
	pathKey := resolvePath(fspath)
	overlayMu.RLock()
	f, ok := overlay[pathKey]
	overlayMu.RUnlock()
	if !ok {
		return nil, os.ErrNotExist
	}
	return f.data, nil
}

func memfsStat(fspath string) (os.FileInfo, error) {
	pathKey := resolvePath(fspath)
	overlayMu.RLock()
	f, ok := overlay[pathKey]
	overlayMu.RUnlock()
	if !ok {
		return nil, os.ErrNotExist
	}
	return &memFileInfo{pathKey, int64(len(f.data)), f.modtime}, nil
}
