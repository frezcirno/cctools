package main

import (
	"log"
	"os"
	"path/filepath"
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
}

func fsStore(fspath string, data []byte) {
	if FS_IS_READONLY {
		fsStoreFake(fspath, data)
	} else {
		fsStoreReal(fspath, data)
	}
}

func fsStoreReal(fspath string, data []byte) {
	key := resolvePath(fspath)
	err := os.WriteFile(key, data, 0644)
	if err != nil {
		log.Println("Error writing file to real fs:", err)
	}
}

func fsLoad(fspath string) []byte {
	if FS_IS_READONLY {
		return fsLoadFake(fspath)
	}
	return fsLoadReal(fspath)
}

func fsLoadReal(fspath string) []byte {
	key := resolvePath(fspath)
	data, err := os.ReadFile(key)
	if err != nil {
		log.Println("Error reading file from real fs:", err)
	}
	return data
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

var FAKEFS = map[string][]byte{}

func fsStoreFake(fspath string, data []byte) {
	key := resolvePath(fspath)
	FAKEFS[key] = data
}

func fsLoadFake(fspath string) []byte {
	key := resolvePath(fspath)
	return FAKEFS[key]
}
