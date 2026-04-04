package main

import (
	"reflect"
	"testing"
)

func TestDictListPreservesInsertionOrder(t *testing.T) {
	dl := NewEmptyDictList()
	dl.set("c", YamlStrDict{"name": "c"})
	dl.set("a", YamlStrDict{"name": "a"})
	dl.set("b", YamlStrDict{"name": "b"})

	want := []string{"c", "a", "b"}
	got := dl.keys()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("keys() = %v, want %v", got, want)
	}
}

func TestDictListValuesInOrder(t *testing.T) {
	dl := NewEmptyDictList()
	dl.set("x", YamlStrDict{"name": "x", "val": 1})
	dl.set("y", YamlStrDict{"name": "y", "val": 2})

	vals := dl.values()
	if len(vals) != 2 {
		t.Fatalf("values() len = %d, want 2", len(vals))
	}
	if vals[0]["val"] != 1 || vals[1]["val"] != 2 {
		t.Fatalf("values() order is wrong: %v", vals)
	}
}

func TestDictListSetOverwriteDoesNotDuplicate(t *testing.T) {
	dl := NewEmptyDictList()
	dl.set("a", YamlStrDict{"name": "a", "v": 1})
	dl.set("b", YamlStrDict{"name": "b", "v": 2})
	dl.set("a", YamlStrDict{"name": "a", "v": 3})

	if dl.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", dl.Len())
	}
	keys := dl.keys()
	want := []string{"a", "b"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("keys() = %v, want %v", keys, want)
	}
	if dl.get("a")["v"] != 3 {
		t.Fatalf("get(a).v = %v, want 3", dl.get("a")["v"])
	}
}

func TestDictListDel(t *testing.T) {
	dl := NewEmptyDictList()
	dl.set("a", YamlStrDict{"name": "a"})
	dl.set("b", YamlStrDict{"name": "b"})
	dl.set("c", YamlStrDict{"name": "c"})

	dl.del("b")

	if dl.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", dl.Len())
	}
	want := []string{"a", "c"}
	got := dl.keys()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("keys() = %v, want %v", got, want)
	}
	if dl.get("b") != nil {
		t.Fatal("get(b) should return nil after delete")
	}
}

func TestDictListUpdate(t *testing.T) {
	dl1 := NewEmptyDictList()
	dl1.set("a", YamlStrDict{"name": "a"})

	dl2 := NewEmptyDictList()
	dl2.set("b", YamlStrDict{"name": "b"})
	dl2.set("c", YamlStrDict{"name": "c"})

	dl1.update(dl2)

	want := []string{"a", "b", "c"}
	got := dl1.keys()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("keys() = %v, want %v", got, want)
	}
}

func TestDictListGetMissing(t *testing.T) {
	dl := NewEmptyDictList()
	if dl.get("nonexistent") != nil {
		t.Fatal("get should return nil for missing key")
	}
}

func TestDictListEach(t *testing.T) {
	dl := NewEmptyDictList()
	dl.set("x", YamlStrDict{"name": "x"})
	dl.set("y", YamlStrDict{"name": "y"})

	var visited []string
	dl.each(func(key string, _ YamlStrDict) {
		visited = append(visited, key)
	})

	want := []string{"x", "y"}
	if !reflect.DeepEqual(visited, want) {
		t.Fatalf("each() visited = %v, want %v", visited, want)
	}
}
