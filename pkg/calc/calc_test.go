package calc

import (
	"testing"

	"github.com/pjbgf/go-test/should"
)

func TestSum(t *testing.T) {
	assertThat := func(assumption string, value1, value2, expected int) {
		should := should.New(t)

		actual := Sum(value1, value2)

		should.BeEqual(expected, actual, assumption)
	}

	assertThat("should return 13 for args 4 and 9", 4, 9, 13)
	assertThat("should return 50 for args 15 and 30", 15, 35, 50)
}
