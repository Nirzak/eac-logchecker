package eaclogchecker

import (
	"reflect"
	"testing"
)

var (
	logGood = Result{Message: "Log entry is fine!", Status: "OK"}
	logNo   = Result{Message: "Log entry has no checksum!", Status: "NO"}
	logBad  = Result{Message: "Log entry was modified, checksum incorrect!", Status: "BAD"}
)

var logTestCases = []struct {
	path     string
	expected []Result
}{
	{"../logs/01.log", []Result{logGood, logGood}},
	{"../logs/02.log", []Result{logGood}},
	{"../logs/03.log", []Result{logNo}},
	{"../logs/04.log", []Result{logGood, logNo}},
	{"../logs/05.log", []Result{logGood, logGood}},
	{"../logs/06.log", []Result{logNo}},
	{"../logs/07.log", []Result{logNo}},
	{"../logs/08.log", []Result{logBad}},
	{"../logs/09.log", []Result{logNo}},
	{"../logs/10.log", []Result{logNo}},
	{"../logs/11.log", []Result{logNo}},
	{"../logs/12.log", []Result{logGood}},
	{"../logs/13.log", []Result{logGood}},
	{"../logs/14.log", []Result{logNo}},
	{"../logs/15.log", []Result{logBad}},
	{"../logs/16.log", []Result{logBad}},
	{"../logs/17.log", []Result{logNo}},
	{"../logs/18.log", []Result{logGood}},
	{"../logs/19.log", []Result{logNo}},
	{"../logs/20.log", []Result{logNo}},
	{"../logs/21.log", []Result{logNo}},
	{"../logs/22.log", []Result{logNo}},
	{"../logs/23.log", []Result{logNo}},
	{"../logs/24.log", []Result{logNo}},
	{"../logs/25.log", []Result{logGood, logNo}},
	{"../logs/26.log", []Result{logBad}},
	{"../logs/27.log", []Result{logGood, logBad, logBad, logBad}},
}

func TestLogChecksum(t *testing.T) {
	for _, tc := range logTestCases {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			actual := CheckChecksum(tc.path)
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("%s:\n  got  %+v\n  want %+v", tc.path, actual, tc.expected)
			}
		})
	}
}
