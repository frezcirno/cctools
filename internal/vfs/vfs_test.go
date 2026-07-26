package vfs

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
)

var keySeq atomic.Int64

// tmpKey returns a path unique to this test run, so tests never collide in the
// process-wide overlay map.
func tmpKey(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("/tmp/vfs_test_%s_%d", t.Name(), keySeq.Add(1))
}

func TestMemfsStoreLoadRoundTrip(t *testing.T) {
	key := tmpKey(t)
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
	_, err := memfsLoad(tmpKey(t))
	if err == nil {
		t.Fatal("memfsLoad should return error for missing key")
	}
	if err != os.ErrNotExist {
		t.Fatalf("memfsLoad error = %v, want os.ErrNotExist", err)
	}
}

func TestMemfsStatReturnsCorrectInfo(t *testing.T) {
	key := tmpKey(t)
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
	_, err := memfsStat(tmpKey(t))
	if err == nil {
		t.Fatal("memfsStat should return error for missing key")
	}
}

func TestMemfsConcurrentAccess(t *testing.T) {
	var wg sync.WaitGroup
	key := tmpKey(t)

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
