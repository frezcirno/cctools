package main

type (
	YamlStrDict map[string]interface{}
)

type DictList map[string]YamlStrDict

func NewDictList(in []interface{}) DictList {
	dl := DictList{}
	for _, elm := range in {
		elm := elm.(map[interface{}]interface{})
		name := elm["name"].(string)
		value := YamlStrDict{}
		for k, v := range elm {
			value[k.(string)] = v
		}
		dl[name] = value
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
