package kfunc

import "github.com/jschwinger233/skbdump/bpf"

type Kfunc struct {
}

func (kf *Kfunc) Attach(objs bpf.Objects) error {
	return nil
}

func (kf *Kfunc) Detach() error {
	return nil
}

func GetSkbfuncs(kfunc string) ([]*Kfunc, error) {
	return nil, nil
}
