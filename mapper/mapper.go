package mapper

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/open-policy-agent/opa/rego"
)

type Mapper struct {
	rego.ResultSet
}

func With(rs rego.ResultSet) *Mapper {
	return &Mapper{
		ResultSet: rs,
	}
}

func (m Mapper) ToSignatureMetadata() (types.SignatureMetadata, error) {
	if m.isEmpty() {
		return types.SignatureMetadata{}, errors.New("empty result set")
	}
	resJSON, err := json.Marshal(m.ResultSet[0].Expressions[0].Value)
	if err != nil {
		return types.SignatureMetadata{}, err
	}
	dec := json.NewDecoder(bytes.NewBuffer(resJSON))
	dec.UseNumber()
	var res types.SignatureMetadata
	err = dec.Decode(&res)
	if err != nil {
		return types.SignatureMetadata{}, err
	}
	return res, nil
}

func (m Mapper) ToSignatureMetadataAll() (map[string]types.SignatureMetadata, error) {
	if m.isEmpty() {
		return nil, errors.New("empty result set")
	}
	resJSON, err := json.Marshal(m.ResultSet[0].Expressions[0].Value)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewBuffer(resJSON))
	dec.UseNumber()
	var res map[string]types.SignatureMetadata
	err = dec.Decode(&res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (m Mapper) ToSelectedEvents() ([]types.SignatureEventSelector, error) {
	if m.isEmpty() {
		return nil, errors.New("empty result set")
	}
	resJSON, err := json.Marshal(m.ResultSet[0].Expressions[0].Value)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewBuffer(resJSON))
	dec.UseNumber()
	var res []types.SignatureEventSelector
	err = dec.Decode(&res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (m Mapper) ToSelectedEventsAll() (map[string][]types.SignatureEventSelector, error) {
	if m.isEmpty() {
		return nil, errors.New("empty result set")
	}
	resJSON, err := json.Marshal(m.ResultSet[0].Expressions[0].Value)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewBuffer(resJSON))
	dec.UseNumber()
	var res map[string][]types.SignatureEventSelector
	err = dec.Decode(&res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (m Mapper) isEmpty() bool {
	rs := m.ResultSet
	return len(rs) == 0 || len(rs[0].Expressions) == 0 || rs[0].Expressions[0].Value == nil
}
