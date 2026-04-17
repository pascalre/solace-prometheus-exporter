package semp

import (
	"testing"
)

func BenchmarkEncodeMetricMulti(b *testing.B) {
	item := "cherry"
	refItems := []string{"apple", "banana", "cherry", "date", "elderberry", "fig", "grape"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encodeMetricMulti(item, refItems)
	}
}

func BenchmarkEncodeMetricMultiCaseInsensitive(b *testing.B) {
	item := "CHERRY"
	refItems := []string{"apple", "banana", "cherry", "date", "elderberry", "fig", "grape"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encodeMetricMulti(item, refItems)
	}
}

func BenchmarkEncodeMetricMultiLong(b *testing.B) {
	item := "item99"
	refItems := make([]string, 100)
	for i := 0; i < 100; i++ {
		refItems[i] = "item" + string(rune(i))
	}
	refItems[99] = "item99"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encodeMetricMulti(item, refItems)
	}
}
