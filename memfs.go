package main

import (
	"log"
	"os"
	"path/filepath"
)

var FAKEFS = map[string][]byte{}

func memfsStore(fspath string, data []byte) {
	key := resolvePath(fspath)
	FAKEFS[key] = data

	// try write to real file
	err := os.WriteFile(key, data, 0644)
	if err != nil {
		log.Println("Error writing file to real fs:", err)
	}
}

func memfsLoad(fspath string) []byte {
	key := resolvePath(fspath)
	return FAKEFS[key]
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
