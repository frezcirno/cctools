package main

import (
	"os"
	"sync"
	"testing"
)

func TestMemfsStoreLoadRoundTrip(t *testing.T) {
	key := "/tmp/test_memfs_" + randomStr(8)
	data := []byte("test data")

	memfsStore(key, data)

	loaded, err := memfsLoad(key)
	if err != nil {
		t.Fatalf("memfsLoad() error = %v", err)
	}
	if string(loaded) != string(data) {
		t.Fatalf("memfsLoad() = %q, want %q", loaded, data)
	}
}

func TestMemfsLoadReturnsErrNotExist(t *testing.T) {
	_, err := memfsLoad("/tmp/nonexistent_" + randomStr(8))
	if err == nil {
		t.Fatal("memfsLoad should return error for missing key")
	}
	if err != os.ErrNotExist {
		t.Fatalf("memfsLoad error = %v, want os.ErrNotExist", err)
	}
}

func TestMemfsStatReturnsCorrectInfo(t *testing.T) {
	key := "/tmp/test_memfs_stat_" + randomStr(8)
	data := []byte("hello world")

	memfsStore(key, data)

	info, err := memfsStat(key)
	if err != nil {
		t.Fatalf("memfsStat() error = %v", err)
	}
	if info.Size() != int64(len(data)) {
		t.Fatalf("Size() = %d, want %d", info.Size(), len(data))
	}
	if info.IsDir() {
		t.Fatal("IsDir() should be false")
	}
}

func TestMemfsStatReturnsErrForMissing(t *testing.T) {
	_, err := memfsStat("/tmp/nonexistent_" + randomStr(8))
	if err == nil {
		t.Fatal("memfsStat should return error for missing key")
	}
}

func TestMemfsConcurrentAccess(t *testing.T) {
	var wg sync.WaitGroup
	key := "/tmp/test_concurrent_" + randomStr(8)

	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(val int) {
			defer wg.Done()
			memfsStore(key, []byte{byte(val)})
		}(i)
		go func() {
			defer wg.Done()
			memfsLoad(key)
		}()
	}
	wg.Wait()
}
