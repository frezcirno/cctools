package clash

import "fmt"

/**
 * DictList is an ordered collection of YamlStrDicts, keyed by name.
 * It preserves insertion order for deterministic output.
 */
type DictList struct {
	order []string
	items map[string]YamlStrDict
}

// NewDictList builds a DictList from a list of YAML maps, keyed by each map's
// "name" field. It returns an error (rather than panicking) on malformed input
// so that untrusted upstream content can be rejected gracefully.
func NewDictList(in []any) (DictList, error) {
	dl := DictList{items: map[string]YamlStrDict{}}
	for idx, elm := range in {
		value, err := asStringAnyMap(elm, fmt.Sprintf("dictlist[%d]", idx))
		if err != nil {
			return DictList{}, err
		}
		name, err := asString(value["name"], fmt.Sprintf("dictlist[%d].name", idx))
		if err != nil {
			return DictList{}, err
		}
		dl.Set(name, YamlStrDict(value))
	}
	return dl, nil
}

func NewEmptyDictList() DictList {
	return DictList{items: map[string]YamlStrDict{}}
}

func (dl *DictList) Get(key string) YamlStrDict {
	if v, ok := dl.items[key]; ok {
		return v
	}
	return nil
}

func (dl *DictList) Set(key string, value YamlStrDict) {
	if value != nil {
		value["name"] = key
	}
	if _, exists := dl.items[key]; !exists {
		dl.order = append(dl.order, key)
	}
	dl.items[key] = value
}

func (dl *DictList) Del(key string) {
	if _, ok := dl.items[key]; !ok {
		return
	}
	delete(dl.items, key)
	for i, k := range dl.order {
		if k == key {
			dl.order = append(dl.order[:i], dl.order[i+1:]...)
			break
		}
	}
}

func (dl *DictList) Update(rhs DictList) {
	for _, k := range rhs.order {
		dl.Set(k, rhs.items[k])
	}
}

func (dl *DictList) Keys() []string {
	res := make([]string, len(dl.order))
	copy(res, dl.order)
	return res
}

func (dl *DictList) Values() []YamlStrDict {
	res := make([]YamlStrDict, 0, len(dl.order))
	for _, k := range dl.order {
		res = append(res, dl.items[k])
	}
	return res
}

func (dl *DictList) Len() int {
	return len(dl.order)
}

// ForEach iterates over the DictList in insertion order.
func (dl *DictList) ForEach(fn func(key string, value YamlStrDict)) {
	for _, k := range dl.order {
		fn(k, dl.items[k])
	}
}
