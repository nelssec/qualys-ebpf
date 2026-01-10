package ai

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"
)

func TestDefaultDetectorConfig(t *testing.T) {
	config := DefaultDetectorConfig()

	if config.ZScoreThreshold != 3.0 {
		t.Errorf("expected ZScoreThreshold 3.0, got %f", config.ZScoreThreshold)
	}
	if config.IQRMultiplier != 1.5 {
		t.Errorf("expected IQRMultiplier 1.5, got %f", config.IQRMultiplier)
	}
	if config.NumTrees != 100 {
		t.Errorf("expected NumTrees 100, got %d", config.NumTrees)
	}
	if config.SampleSize != 256 {
		t.Errorf("expected SampleSize 256, got %d", config.SampleSize)
	}
}

func TestNewAIDetector(t *testing.T) {
	config := DefaultDetectorConfig()
	detector := NewAIDetector(config)

	if detector == nil {
		t.Fatal("expected non-nil detector")
	}
	if detector.baselines == nil {
		t.Error("expected initialized baselines map")
	}
	if detector.timeSeries == nil {
		t.Error("expected initialized timeSeries map")
	}
}

func TestAnomalyCallback(t *testing.T) {
	config := DefaultDetectorConfig()
	config.LearningPeriod = 0 // Disable learning period for testing
	detector := NewAIDetector(config)

	var receivedAnomaly *Anomaly
	var mu sync.Mutex
	detector.SetAnomalyCallback(func(a *Anomaly) {
		mu.Lock()
		receivedAnomaly = a
		mu.Unlock()
	})

	// Create baseline with enough data
	baseline := detector.getOrCreateBaseline("test-container")
	baseline.InLearning = false
	baseline.SampleCount = 100
	baseline.Features = map[string]*FeatureStats{
		"cpu": {
			Name:       "cpu",
			Count:      100,
			Sum:        5000,  // mean = 50
			SumSquares: 260000, // variance = 100, std = 10
			Min:        30,
			Max:        70,
			Values:     generateNormalValues(100, 50, 10),
			MaxValues:  1000,
		},
	}

	// Send anomalous value (z-score > 3)
	fv := &FeatureVector{
		Timestamp:   time.Now(),
		ContainerID: "test-container",
		Features:    map[string]float64{"cpu": 100}, // 5 std devs above mean
	}

	anomalies := detector.Analyze(context.Background(), fv)

	if len(anomalies) == 0 {
		t.Error("expected at least one anomaly")
	}

	// Wait for callback
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	if receivedAnomaly == nil {
		t.Error("expected callback to be invoked")
	}
	mu.Unlock()
}

func TestStatisticalAnomalyDetection(t *testing.T) {
	config := DefaultDetectorConfig()
	config.ZScoreThreshold = 3.0
	detector := NewAIDetector(config)

	// Create baseline
	baseline := &FeatureBaseline{
		ContainerID: "test",
		InLearning:  false,
		SampleCount: 100,
		Features: map[string]*FeatureStats{
			"memory": {
				Name:       "memory",
				Count:      100,
				Sum:        10000, // mean = 100
				SumSquares: 1100000, // variance = 1000, std ≈ 31.6
				Min:        50,
				Max:        150,
				Values:     generateNormalValues(100, 100, 31.6),
				MaxValues:  1000,
			},
		},
	}
	detector.baselines["test"] = baseline

	tests := []struct {
		name     string
		value    float64
		isAnomaly bool
	}{
		{"normal_value", 100, false},
		{"slightly_high", 130, false},
		{"very_high", 250, true}, // ~4.7 std devs
		{"very_low", -50, true},  // ~-4.7 std devs
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fv := &FeatureVector{
				Timestamp:   time.Now(),
				ContainerID: "test",
				Features:    map[string]float64{"memory": tt.value},
			}
			anomalies := detector.detectStatisticalAnomalies(fv, baseline)
			hasAnomaly := len(anomalies) > 0
			if hasAnomaly != tt.isAnomaly {
				t.Errorf("value %f: expected anomaly=%v, got %v", tt.value, tt.isAnomaly, hasAnomaly)
			}
		})
	}
}

func TestTimeSeriesAnomalyDetection(t *testing.T) {
	config := DefaultDetectorConfig()
	config.TrendWindow = 10
	config.MADThreshold = 3.0
	detector := NewAIDetector(config)

	// Create time series with stable values
	containerID := "ts-test"
	featureName := "requests"
	key := containerID + ":" + featureName

	points := make([]*TimeSeriesPoint, 100)
	baseTime := time.Now().Add(-100 * time.Minute)
	for i := 0; i < 100; i++ {
		points[i] = &TimeSeriesPoint{
			Timestamp: baseTime.Add(time.Duration(i) * time.Minute),
			Value:     100 + float64(i%5), // Stable around 100
		}
	}
	detector.timeSeries[key] = points

	// Test normal value
	fv := &FeatureVector{
		Timestamp:   time.Now(),
		ContainerID: containerID,
		Features:    map[string]float64{featureName: 102},
	}
	anomalies := detector.detectTimeSeriesAnomalies(fv)
	if len(anomalies) > 0 {
		t.Error("expected no anomalies for normal value")
	}

	// Test anomalous value
	fv.Features[featureName] = 500 // Way above normal
	anomalies = detector.detectTimeSeriesAnomalies(fv)
	if len(anomalies) == 0 {
		t.Error("expected anomaly for spike value")
	}
}

func TestIsolationForest(t *testing.T) {
	forest := NewIsolationForest(10, 32)

	// Create normal samples
	samples := make([]map[string]float64, 100)
	for i := 0; i < 100; i++ {
		samples[i] = map[string]float64{
			"feature1": float64(50 + i%10),
			"feature2": float64(100 + i%20),
		}
	}

	forest.Fit(samples)

	// Test normal sample
	normalSample := map[string]float64{
		"feature1": 55,
		"feature2": 110,
	}
	normalScore := forest.Score(normalSample)
	if normalScore > 0.6 {
		t.Errorf("expected normal sample to have low score, got %f", normalScore)
	}

	// Test anomalous sample
	anomalousSample := map[string]float64{
		"feature1": 500,
		"feature2": 1000,
	}
	anomalyScore := forest.Score(anomalousSample)
	if anomalyScore < 0.5 {
		t.Errorf("expected anomalous sample to have high score, got %f", anomalyScore)
	}
}

func TestKMeansClustering(t *testing.T) {
	// Create two distinct clusters
	samples := make([]map[string]float64, 20)
	containerIDs := make([]string, 20)

	// Cluster 1: low values
	for i := 0; i < 10; i++ {
		samples[i] = map[string]float64{"x": float64(10 + i), "y": float64(10 + i)}
		containerIDs[i] = "low-" + string(rune('a'+i))
	}
	// Cluster 2: high values
	for i := 10; i < 20; i++ {
		samples[i] = map[string]float64{"x": float64(100 + i), "y": float64(100 + i)}
		containerIDs[i] = "high-" + string(rune('a'+i-10))
	}

	clusters := kMeansClustering(samples, containerIDs, 2, 50)

	if len(clusters) != 2 {
		t.Errorf("expected 2 clusters, got %d", len(clusters))
	}

	// Check that clusters have members
	for i, cluster := range clusters {
		if len(cluster.Members) == 0 {
			t.Errorf("cluster %d has no members", i)
		}
	}
}

func TestCalculateQuartiles(t *testing.T) {
	values := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	q1, q3 := calculateQuartiles(values)

	// For 12 values, Q1 = value at index n/4 = 3, Q3 = value at index 3n/4 = 9
	// Actual implementation: sorted[n/4] = sorted[3] = 4, sorted[3*n/4] = sorted[9] = 10
	if q1 != 4 {
		t.Errorf("expected Q1=4, got %f", q1)
	}
	if q3 != 10 {
		t.Errorf("expected Q3=10, got %f", q3)
	}
}

func TestCalculateMovingAverage(t *testing.T) {
	points := []*TimeSeriesPoint{
		{Value: 10},
		{Value: 20},
		{Value: 30},
		{Value: 40},
		{Value: 50},
	}
	avg := calculateMovingAverage(points)
	expected := 30.0
	if avg != expected {
		t.Errorf("expected %f, got %f", expected, avg)
	}

	// Empty case
	emptyAvg := calculateMovingAverage([]*TimeSeriesPoint{})
	if emptyAvg != 0 {
		t.Errorf("expected 0 for empty, got %f", emptyAvg)
	}
}

func TestCalculateMovingStd(t *testing.T) {
	points := []*TimeSeriesPoint{
		{Value: 10},
		{Value: 20},
		{Value: 30},
		{Value: 40},
		{Value: 50},
	}
	mean := 30.0
	std := calculateMovingStd(points, mean)

	// Manually calculated: sqrt((400+100+0+100+400)/4) = sqrt(250) ≈ 15.81
	expected := math.Sqrt(250)
	if math.Abs(std-expected) > 0.01 {
		t.Errorf("expected ~%f, got %f", expected, std)
	}
}

func TestCalculateTrend(t *testing.T) {
	// Positive trend
	posPoints := []*TimeSeriesPoint{
		{Value: 10},
		{Value: 20},
		{Value: 30},
		{Value: 40},
		{Value: 50},
	}
	trend := calculateTrend(posPoints)
	if trend <= 0 {
		t.Errorf("expected positive trend, got %f", trend)
	}

	// Negative trend
	negPoints := []*TimeSeriesPoint{
		{Value: 50},
		{Value: 40},
		{Value: 30},
		{Value: 20},
		{Value: 10},
	}
	trend = calculateTrend(negPoints)
	if trend >= 0 {
		t.Errorf("expected negative trend, got %f", trend)
	}

	// No trend
	flatPoints := []*TimeSeriesPoint{
		{Value: 30},
		{Value: 30},
		{Value: 30},
		{Value: 30},
	}
	trend = calculateTrend(flatPoints)
	if math.Abs(trend) > 0.001 {
		t.Errorf("expected zero trend, got %f", trend)
	}
}

func TestEuclideanDistance(t *testing.T) {
	a := map[string]float64{"x": 0, "y": 0}
	b := map[string]float64{"x": 3, "y": 4}

	dist := euclideanDistance(a, b)
	expected := 5.0 // 3-4-5 triangle
	if math.Abs(dist-expected) > 0.001 {
		t.Errorf("expected %f, got %f", expected, dist)
	}
}

func TestCalculateConfidence(t *testing.T) {
	tests := []struct {
		sampleCount int
		minExpected float64
		maxExpected float64
	}{
		{1, 0.0, 0.02},
		{100, 0.6, 0.7},
		{500, 0.99, 1.0},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			conf := calculateConfidence(tt.sampleCount)
			if conf < tt.minExpected || conf > tt.maxExpected {
				t.Errorf("sampleCount=%d: expected [%f,%f], got %f",
					tt.sampleCount, tt.minExpected, tt.maxExpected, conf)
			}
		})
	}
}

func TestRandomInt(t *testing.T) {
	// Test that randomInt returns values in range
	for i := 0; i < 100; i++ {
		val := randomInt(10)
		if val < 0 || val >= 10 {
			t.Errorf("randomInt(10) returned %d, expected [0,10)", val)
		}
	}

	// Test edge cases
	if randomInt(0) != 0 {
		t.Error("randomInt(0) should return 0")
	}
	if randomInt(-5) != 0 {
		t.Error("randomInt(-5) should return 0")
	}
	if randomInt(1) != 0 {
		t.Error("randomInt(1) should return 0")
	}
}

func TestRandomFloat(t *testing.T) {
	// Test that randomFloat returns values in [0, 1)
	for i := 0; i < 100; i++ {
		val := randomFloat()
		if val < 0 || val >= 1 {
			t.Errorf("randomFloat() returned %f, expected [0,1)", val)
		}
	}
}

func TestAnalyzeConcurrent(t *testing.T) {
	config := DefaultDetectorConfig()
	config.LearningPeriod = 0
	detector := NewAIDetector(config)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				fv := &FeatureVector{
					Timestamp:   time.Now(),
					ContainerID: "container-" + string(rune('0'+id)),
					Features:    map[string]float64{"cpu": float64(50 + j%20)},
				}
				detector.Analyze(context.Background(), fv)
			}
		}(i)
	}
	wg.Wait()

	stats := detector.Stats()
	analyzed := stats["total_analyzed"].(int64)
	if analyzed != 1000 {
		t.Errorf("expected 1000 analyses, got %d", analyzed)
	}
}

func TestDetectorStats(t *testing.T) {
	config := DefaultDetectorConfig()
	detector := NewAIDetector(config)

	stats := detector.Stats()
	if stats["total_analyzed"].(int64) != 0 {
		t.Error("expected 0 total_analyzed initially")
	}
	if stats["anomalies_found"].(int64) != 0 {
		t.Error("expected 0 anomalies_found initially")
	}
}

func TestBootstrapSample(t *testing.T) {
	samples := make([]map[string]float64, 10)
	for i := 0; i < 10; i++ {
		samples[i] = map[string]float64{"x": float64(i)}
	}

	bootstrap := bootstrapSample(samples, 5)
	if len(bootstrap) != 5 {
		t.Errorf("expected 5 samples, got %d", len(bootstrap))
	}

	// Test with size larger than samples
	bootstrap = bootstrapSample(samples, 20)
	if len(bootstrap) != 10 {
		t.Errorf("expected 10 samples (capped), got %d", len(bootstrap))
	}
}

// Helper function to generate normally distributed values
func generateNormalValues(n int, mean, std float64) []float64 {
	values := make([]float64, n)
	for i := 0; i < n; i++ {
		// Simple approximation using central limit theorem
		sum := 0.0
		for j := 0; j < 12; j++ {
			sum += randomFloat()
		}
		values[i] = mean + (sum-6)*std
	}
	return values
}

// Benchmarks

func BenchmarkAnalyze(b *testing.B) {
	config := DefaultDetectorConfig()
	config.LearningPeriod = 0
	detector := NewAIDetector(config)

	// Pre-populate baseline
	for i := 0; i < 100; i++ {
		fv := &FeatureVector{
			Timestamp:   time.Now(),
			ContainerID: "bench-container",
			Features:    map[string]float64{"cpu": float64(50 + i%20), "memory": float64(1000 + i%100)},
		}
		detector.Analyze(context.Background(), fv)
	}

	// Mark as not learning
	detector.mu.Lock()
	if baseline, ok := detector.baselines["bench-container"]; ok {
		baseline.InLearning = false
	}
	detector.mu.Unlock()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		fv := &FeatureVector{
			Timestamp:   time.Now(),
			ContainerID: "bench-container",
			Features:    map[string]float64{"cpu": float64(50 + i%20), "memory": float64(1000 + i%100)},
		}
		detector.Analyze(context.Background(), fv)
	}
}

func BenchmarkStatisticalDetection(b *testing.B) {
	config := DefaultDetectorConfig()
	detector := NewAIDetector(config)

	baseline := &FeatureBaseline{
		ContainerID: "bench",
		InLearning:  false,
		SampleCount: 1000,
		Features: map[string]*FeatureStats{
			"cpu": {
				Name:       "cpu",
				Count:      1000,
				Sum:        50000,
				SumSquares: 2600000,
				Min:        30,
				Max:        70,
				Values:     generateNormalValues(1000, 50, 10),
				MaxValues:  1000,
			},
			"memory": {
				Name:       "memory",
				Count:      1000,
				Sum:        1000000,
				SumSquares: 1100000000,
				Min:        800,
				Max:        1200,
				Values:     generateNormalValues(1000, 1000, 100),
				MaxValues:  1000,
			},
		},
	}
	detector.baselines["bench"] = baseline

	fv := &FeatureVector{
		Timestamp:   time.Now(),
		ContainerID: "bench",
		Features:    map[string]float64{"cpu": 55, "memory": 1050},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		detector.detectStatisticalAnomalies(fv, baseline)
	}
}

func BenchmarkIsolationForestFit(b *testing.B) {
	samples := make([]map[string]float64, 256)
	for i := 0; i < 256; i++ {
		samples[i] = map[string]float64{
			"feature1": float64(i % 100),
			"feature2": float64((i * 2) % 100),
			"feature3": float64((i * 3) % 100),
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		forest := NewIsolationForest(100, 256)
		forest.Fit(samples)
	}
}

func BenchmarkIsolationForestScore(b *testing.B) {
	samples := make([]map[string]float64, 256)
	for i := 0; i < 256; i++ {
		samples[i] = map[string]float64{
			"feature1": float64(i % 100),
			"feature2": float64((i * 2) % 100),
			"feature3": float64((i * 3) % 100),
		}
	}

	forest := NewIsolationForest(100, 256)
	forest.Fit(samples)

	testSample := map[string]float64{
		"feature1": 50,
		"feature2": 50,
		"feature3": 50,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		forest.Score(testSample)
	}
}

func BenchmarkKMeansClustering(b *testing.B) {
	samples := make([]map[string]float64, 100)
	containerIDs := make([]string, 100)
	for i := 0; i < 100; i++ {
		samples[i] = map[string]float64{
			"x": float64(i % 50),
			"y": float64((i * 2) % 50),
		}
		containerIDs[i] = "container-" + string(rune('a'+i%26))
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		kMeansClustering(samples, containerIDs, 5, 50)
	}
}

func BenchmarkEuclideanDistance(b *testing.B) {
	a := map[string]float64{"x": 10, "y": 20, "z": 30}
	c := map[string]float64{"x": 15, "y": 25, "z": 35}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		euclideanDistance(a, c)
	}
}

func BenchmarkCalculateQuartiles(b *testing.B) {
	values := make([]float64, 1000)
	for i := 0; i < 1000; i++ {
		values[i] = float64(i)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		calculateQuartiles(values)
	}
}

func BenchmarkConcurrentAnalysis(b *testing.B) {
	config := DefaultDetectorConfig()
	config.LearningPeriod = 0
	detector := NewAIDetector(config)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			fv := &FeatureVector{
				Timestamp:   time.Now(),
				ContainerID: "concurrent-test",
				Features:    map[string]float64{"cpu": 50, "memory": 1000},
			}
			detector.Analyze(context.Background(), fv)
		}
	})
}
