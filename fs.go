package main

import (
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var FS_IS_READONLY = false

func init() {
	// Test if the filesystem is read-only
	os.Remove(".ct_test_fs")
	_, err := os.OpenFile(".ct_test_fs", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		log.Println("Filesystem is read-only")
		FS_IS_READONLY = true
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

func fsStore(fspath string, data []byte) {
	if FS_IS_READONLY {
		memfsStore(fspath, data)
	} else {
		fileStore(fspath, data)
	}
}

func fsLoad(fspath string) ([]byte, error) {
	if FS_IS_READONLY {
		// try to load from memory first
		if data, err := memfsLoad(fspath); err == nil {
			return data, nil
		}
	}
	return fileLoad(fspath)
}

func fsStat(fspath string) (os.FileInfo, error) {
	if FS_IS_READONLY {
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

type File struct {
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
	OVERLAYFS = map[string]File{}
)

func memfsStore(fspath string, data []byte) {
	pathKey := resolvePath(fspath)
	overlayMu.Lock()
	OVERLAYFS[pathKey] = File{data, time.Now()}
	overlayMu.Unlock()
}

func memfsLoad(fspath string) ([]byte, error) {
	pathKey := resolvePath(fspath)
	overlayMu.RLock()
	f, ok := OVERLAYFS[pathKey]
	overlayMu.RUnlock()
	if !ok {
		return nil, os.ErrNotExist
	}
	return f.data, nil
}

func memfsStat(fspath string) (os.FileInfo, error) {
	pathKey := resolvePath(fspath)
	overlayMu.RLock()
	f, ok := OVERLAYFS[pathKey]
	overlayMu.RUnlock()
	if !ok {
		return nil, os.ErrNotExist
	}
	return &memFileInfo{pathKey, int64(len(f.data)), f.modtime}, nil
}
