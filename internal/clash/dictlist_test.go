package clash

import (
	"reflect"
	"testing"
)

func TestDictListPreservesInsertionOrder(t *testing.T) {
	dl := NewEmptyDictList()
	dl.Set("c", YamlStrDict{"name": "c"})
	dl.Set("a", YamlStrDict{"name": "a"})
	dl.Set("b", YamlStrDict{"name": "b"})

	want := []string{"c", "a", "b"}
	got := dl.Keys()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("keys() = %v, want %v", got, want)
	}
}

func TestDictListValuesInOrder(t *testing.T) {
	dl := NewEmptyDictList()
	dl.Set("x", YamlStrDict{"name": "x", "val": 1})
	dl.Set("y", YamlStrDict{"name": "y", "val": 2})

	vals := dl.Values()
	if len(vals) != 2 {
		t.Fatalf("values() len = %d, want 2", len(vals))
	}
	if vals[0]["val"] != 1 || vals[1]["val"] != 2 {
		t.Fatalf("values() order is wrong: %v", vals)
	}
}

func TestDictListSetOverwriteDoesNotDuplicate(t *testing.T) {
	dl := NewEmptyDictList()
	dl.Set("a", YamlStrDict{"name": "a", "v": 1})
	dl.Set("b", YamlStrDict{"name": "b", "v": 2})
	dl.Set("a", YamlStrDict{"name": "a", "v": 3})

	if dl.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", dl.Len())
	}
	keys := dl.Keys()
	want := []string{"a", "b"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("keys() = %v, want %v", keys, want)
	}
	if dl.Get("a")["v"] != 3 {
		t.Fatalf("get(a).v = %v, want 3", dl.Get("a")["v"])
	}
}

func TestDictListDel(t *testing.T) {
	dl := NewEmptyDictList()
	dl.Set("a", YamlStrDict{"name": "a"})
	dl.Set("b", YamlStrDict{"name": "b"})
	dl.Set("c", YamlStrDict{"name": "c"})

	dl.Del("b")

	if dl.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", dl.Len())
	}
	want := []string{"a", "c"}
	got := dl.Keys()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("keys() = %v, want %v", got, want)
	}
	if dl.Get("b") != nil {
		t.Fatal("get(b) should return nil after delete")
	}
}

func TestDictListUpdate(t *testing.T) {
	dl1 := NewEmptyDictList()
	dl1.Set("a", YamlStrDict{"name": "a"})

	dl2 := NewEmptyDictList()
	dl2.Set("b", YamlStrDict{"name": "b"})
	dl2.Set("c", YamlStrDict{"name": "c"})

	dl1.Update(dl2)

	want := []string{"a", "b", "c"}
	got := dl1.Keys()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("keys() = %v, want %v", got, want)
	}
}

func TestDictListGetMissing(t *testing.T) {
	dl := NewEmptyDictList()
	if dl.Get("nonexistent") != nil {
		t.Fatal("get should return nil for missing key")
	}
}

func TestNewDictListRejectsMalformedInput(t *testing.T) {
	if _, err := NewDictList([]any{"not-a-map"}); err == nil {
		t.Error("expected error for non-map element, got nil")
	}
	if _, err := NewDictList([]any{map[string]any{"type": "ss"}}); err == nil {
		t.Error("expected error for element missing 'name', got nil")
	}
	dl, err := NewDictList([]any{map[string]any{"name": "ok", "v": 1}})
	if err != nil {
		t.Fatalf("valid input errored: %v", err)
	}
	if dl.Len() != 1 || dl.Get("ok") == nil {
		t.Fatalf("valid input not stored: len=%d", dl.Len())
	}
}

func TestDictListEach(t *testing.T) {
	dl := NewEmptyDictList()
	dl.Set("x", YamlStrDict{"name": "x"})
	dl.Set("y", YamlStrDict{"name": "y"})

	var visited []string
	dl.ForEach(func(key string, _ YamlStrDict) {
		visited = append(visited, key)
	})

	want := []string{"x", "y"}
	if !reflect.DeepEqual(visited, want) {
		t.Fatalf("each() visited = %v, want %v", visited, want)
	}
}
