// Copyright 2018 The Elastos.ELA.SideChain.ESC Authors
// This file is part of the Elastos.ELA.SideChain.ESC library.
//
// The Elastos.ELA.SideChain.ESC library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Elastos.ELA.SideChain.ESC library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the Elastos.ELA.SideChain.ESC library. If not, see <http://www.gnu.org/licenses/>.

package accounts

import (
	"testing"
)

func TestURLParsing(t *testing.T) {
	url, err := parseURL("https://elastos.org")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if url.Scheme != "https" {
		t.Errorf("expected: %v, got: %v", "https", url.Scheme)
	}
	if url.Path != "elastos.org" {
		t.Errorf("expected: %v, got: %v", "elastos.org", url.Path)
	}

	_, err = parseURL("elastos.org")
	if err == nil {
		t.Error("expected err, got: nil")
	}
}

func TestURLString(t *testing.T) {
	url := URL{Scheme: "https", Path: "elastos.org"}
	if url.String() != "https://elastos.org" {
		t.Errorf("expected: %v, got: %v", "https://elastos.org", url.String())
	}

	url = URL{Scheme: "", Path: "elastos.org"}
	if url.String() != "elastos.org" {
		t.Errorf("expected: %v, got: %v", "elastos.org", url.String())
	}
}

func TestURLMarshalJSON(t *testing.T) {
	url := URL{Scheme: "https", Path: "elastos.org"}
	json, err := url.MarshalJSON()
	if err != nil {
		t.Errorf("unexpcted error: %v", err)
	}
	if string(json) != "\"https://elastos.org\"" {
		t.Errorf("expected: %v, got: %v", "\"https://elastos.org\"", string(json))
	}
}

func TestURLUnmarshalJSON(t *testing.T) {
	url := &URL{}
	err := url.UnmarshalJSON([]byte("\"https://elastos.org\""))
	if err != nil {
		t.Errorf("unexpcted error: %v", err)
	}
	if url.Scheme != "https" {
		t.Errorf("expected: %v, got: %v", "https", url.Scheme)
	}
	if url.Path != "elastos.org" {
		t.Errorf("expected: %v, got: %v", "https", url.Path)
	}
}

func TestURLComparison(t *testing.T) {
	tests := []struct {
		urlA   URL
		urlB   URL
		expect int
	}{
		{URL{"https", "elastos.org"}, URL{"https", "elastos.org"}, 0},
		{URL{"http", "elastos.org"}, URL{"https", "elastos.org"}, -1},
		{URL{"https", "elastos.org/a"}, URL{"https", "elastos.org"}, 1},
		{URL{"https", "abc.org"}, URL{"https", "elastos.org"}, -1},
	}

	for i, tt := range tests {
		result := tt.urlA.Cmp(tt.urlB)
		if result != tt.expect {
			t.Errorf("test %d: cmp mismatch: expected: %d, got: %d", i, tt.expect, result)
		}
	}
}
