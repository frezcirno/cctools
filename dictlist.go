package main

import "fmt"

type (
	YamlStrDict map[string]any
)

/**
 * DictList is a map of YamlStrDicts, where the key is the name of the YamlStrDict.
 * It is used to store a list of unique-key dictionaries in the YAML file.
 * Example:
 * {
 *   "dict1": {
 *       name: "dict1",
 *       ...
 *   },
 *   "dict2": {
 *       name: "dict2",
 *       ...
 *   }
 * }
 */
type DictList map[string]YamlStrDict

func NewDictList(in []any) DictList {
	dl := DictList{}
	for idx, elm := range in {
		value, err := asStringAnyMap(elm, fmt.Sprintf("dictlist[%d]", idx))
		if err != nil {
			panic(err)
		}
		name, err := asString(value["name"], fmt.Sprintf("dictlist[%d].name", idx))
		if err != nil {
			panic(err)
		}
		dl[name] = YamlStrDict(value)
	}
	return dl
}

func (dl *DictList) get(key string) YamlStrDict {
	if v, ok := (*dl)[key]; ok {
		return v
	}
	return nil
}

func (dl *DictList) set(key string, value YamlStrDict) {
	if value != nil {
		value["name"] = key
	}
	(*dl)[key] = value
}

func (dl *DictList) update(rhs DictList) {
	for k, v := range rhs {
		(*dl)[k] = v
	}
}

func (dl *DictList) keys() (res []string) {
	for k := range *dl {
		res = append(res, k)
	}
	return
}

func (dl *DictList) values() (res []YamlStrDict) {
	for _, v := range *dl {
		res = append(res, v)
	}
	return
}

func (dl *DictList) Len() int {
	return len(*dl)
}
