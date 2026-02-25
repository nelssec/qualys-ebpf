package ai

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

type AnomalyType string

const (
	AnomalyTypeStatistical AnomalyType = "statistical"
	AnomalyTypeTimeSeries  AnomalyType = "time_series"
	AnomalyTypeBehavioral  AnomalyType = "behavioral"
	AnomalyTypeClustering  AnomalyType = "clustering"
	AnomalyTypeIsolation   AnomalyType = "isolation"
)

type Anomaly struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	Type          AnomalyType            `json:"type"`
	Score         float64                `json:"score"`
	Confidence    float64                `json:"confidence"`
	ContainerID   string                 `json:"containerId,omitempty"`
	ContainerName string                 `json:"containerName,omitempty"`
	Namespace     string                 `json:"namespace,omitempty"`
	Feature       string                 `json:"feature"`
	Value         float64                `json:"value"`
	Expected      float64                `json:"expected"`
	Deviation     float64                `json:"deviation"`
	Description   string                 `json:"description"`
	Context       map[string]interface{} `json:"context,omitempty"`
}

type FeatureVector struct {
	Timestamp     time.Time
	ContainerID   string
	ContainerName string
	Namespace     string
	Features      map[string]float64
}

type TimeSeriesPoint struct {
	Timestamp time.Time
	Value     float64
}

type AIDetector struct {
	mu              sync.RWMutex
	config          DetectorConfig
	baselines       map[string]*FeatureBaseline
	timeSeries      map[string][]*TimeSeriesPoint
	isolationForest *IsolationForest
	clusters        []*Cluster
	onAnomaly       func(*Anomaly)
	totalAnalyzed   int64
	anomaliesFound  int64
	lastTrainingAt  time.Time
}

type DetectorConfig struct {
	ZScoreThreshold    float64       `json:"zScoreThreshold"`
	IQRMultiplier      float64       `json:"iqrMultiplier"`
	SeasonalityPeriod  time.Duration `json:"seasonalityPeriod"`
	TrendWindow        int           `json:"trendWindow"`
	MADThreshold       float64       `json:"madThreshold"`
	NumTrees           int           `json:"numTrees"`
	SampleSize         int           `json:"sampleSize"`
	AnomalyThreshold   float64       `json:"anomalyThreshold"`
	MinClusterSize     int           `json:"minClusterSize"`
	ClusterEpsilon     float64       `json:"clusterEpsilon"`
	LearningPeriod     time.Duration `json:"learningPeriod"`
	RetrainingInterval time.Duration `json:"retrainingInterval"`
	MinSamplesForModel int           `json:"minSamplesForModel"`
}

type FeatureBaseline struct {
	ContainerID string
	FirstSeen   time.Time
	LastUpdated time.Time
	SampleCount int
	Features    map[string]*FeatureStats
	InLearning  bool
}

type FeatureStats struct {
	Name       string
	Count      int
	Sum        float64
	SumSquares float64
	Min        float64
	Max        float64
	Values     []float64
	MaxValues  int
}

type Cluster struct {
	ID        int
	Centroid  map[string]float64
	Members   []string
	Variance  float64
	CreatedAt time.Time
}

type IsolationForest struct {
	Trees      []*IsolationTree
	SampleSize int
	NumTrees   int
}

type IsolationTree struct {
	Root        *IsolationNode
	MaxDepth    int
	NumFeatures int
}

type IsolationNode struct {
	Feature    string
	SplitValue float64
	Left       *IsolationNode
	Right      *IsolationNode
	Size       int
	IsLeaf     bool
}

func DefaultDetectorConfig() DetectorConfig {
	return DetectorConfig{
		ZScoreThreshold:    3.0,
		IQRMultiplier:      1.5,
		SeasonalityPeriod:  24 * time.Hour,
		TrendWindow:        100,
		MADThreshold:       3.0,
		NumTrees:           100,
		SampleSize:         256,
		AnomalyThreshold:   0.6,
		MinClusterSize:     5,
		ClusterEpsilon:     0.5,
		LearningPeriod:     48 * time.Hour,
		RetrainingInterval: 6 * time.Hour,
		MinSamplesForModel: 1000,
	}
}

func NewAIDetector(config DetectorConfig) *AIDetector {
	return &AIDetector{
		config:     config,
		baselines:  make(map[string]*FeatureBaseline),
		timeSeries: make(map[string][]*TimeSeriesPoint),
		clusters:   make([]*Cluster, 0),
	}
}

func (d *AIDetector) SetAnomalyCallback(callback func(*Anomaly)) {
	d.onAnomaly = callback
}

func (d *AIDetector) Analyze(ctx context.Context, fv *FeatureVector) []*Anomaly {
	d.mu.Lock()
	d.totalAnalyzed++
	d.mu.Unlock()

	anomalies := make([]*Anomaly, 0)
	baseline := d.getOrCreateBaseline(fv.ContainerID)
	d.updateBaseline(baseline, fv)

	if baseline.InLearning {
		return anomalies
	}

	statAnomalies := d.detectStatisticalAnomalies(fv, baseline)
	anomalies = append(anomalies, statAnomalies...)

	tsAnomalies := d.detectTimeSeriesAnomalies(fv)
	anomalies = append(anomalies, tsAnomalies...)

	if d.isolationForest != nil {
		ifAnomalies := d.detectIsolationAnomalies(fv)
		anomalies = append(anomalies, ifAnomalies...)
	}

	if len(d.clusters) > 0 {
		clusterAnomalies := d.detectClusteringAnomalies(fv)
		anomalies = append(anomalies, clusterAnomalies...)
	}

	for _, anomaly := range anomalies {
		d.mu.Lock()
		d.anomaliesFound++
		d.mu.Unlock()

		if d.onAnomaly != nil {
			go d.onAnomaly(anomaly)
		}
	}

	return anomalies
}

func (d *AIDetector) getOrCreateBaseline(containerID string) *FeatureBaseline {
	d.mu.Lock()
	defer d.mu.Unlock()

	if baseline, exists := d.baselines[containerID]; exists {
		return baseline
	}

	baseline := &FeatureBaseline{
		ContainerID: containerID,
		FirstSeen:   time.Now(),
		LastUpdated: time.Now(),
		SampleCount: 0,
		Features:    make(map[string]*FeatureStats),
		InLearning:  true,
	}
	d.baselines[containerID] = baseline
	return baseline
}

func (d *AIDetector) updateBaseline(baseline *FeatureBaseline, fv *FeatureVector) {
	d.mu.Lock()
	defer d.mu.Unlock()

	baseline.LastUpdated = time.Now()
	baseline.SampleCount++

	if baseline.InLearning && time.Since(baseline.FirstSeen) > d.config.LearningPeriod {
		baseline.InLearning = false
		fmt.Printf("[AI] Container %s completed learning period (%d samples)\n",
			baseline.ContainerID, baseline.SampleCount)
	}

	for name, value := range fv.Features {
		stats, exists := baseline.Features[name]
		if !exists {
			stats = &FeatureStats{
				Name:      name,
				Min:       value,
				Max:       value,
				Values:    make([]float64, 0),
				MaxValues: 1000,
			}
			baseline.Features[name] = stats
		}

		stats.Count++
		stats.Sum += value
		stats.SumSquares += value * value
		if value < stats.Min {
			stats.Min = value
		}
		if value > stats.Max {
			stats.Max = value
		}

		stats.Values = append(stats.Values, value)
		if len(stats.Values) > stats.MaxValues {
			stats.Values = stats.Values[1:]
		}
	}

	for name, value := range fv.Features {
		key := fmt.Sprintf("%s:%s", fv.ContainerID, name)
		d.timeSeries[key] = append(d.timeSeries[key], &TimeSeriesPoint{
			Timestamp: fv.Timestamp,
			Value:     value,
		})

		maxPoints := 10000
		if len(d.timeSeries[key]) > maxPoints {
			d.timeSeries[key] = d.timeSeries[key][len(d.timeSeries[key])-maxPoints:]
		}
	}
}

func (d *AIDetector) detectStatisticalAnomalies(fv *FeatureVector, baseline *FeatureBaseline) []*Anomaly {
	anomalies := make([]*Anomaly, 0)

	d.mu.RLock()
	defer d.mu.RUnlock()

	for name, value := range fv.Features {
		stats, exists := baseline.Features[name]
		if !exists || stats.Count < 30 {
			continue
		}

		mean := stats.Sum / float64(stats.Count)
		variance := (stats.SumSquares / float64(stats.Count)) - (mean * mean)
		stdDev := math.Sqrt(variance)

		if stdDev == 0 {
			continue
		}

		zScore := (value - mean) / stdDev
		if math.Abs(zScore) > d.config.ZScoreThreshold {
			anomalies = append(anomalies, &Anomaly{
				ID:            fmt.Sprintf("stat-%s-%d", name, time.Now().UnixNano()),
				Timestamp:     fv.Timestamp,
				Type:          AnomalyTypeStatistical,
				Score:         math.Min(100, math.Abs(zScore)*20),
				Confidence:    calculateConfidence(stats.Count),
				ContainerID:   fv.ContainerID,
				ContainerName: fv.ContainerName,
				Namespace:     fv.Namespace,
				Feature:       name,
				Value:         value,
				Expected:      mean,
				Deviation:     zScore,
				Description:   fmt.Sprintf("Feature %s has unusual value (z-score: %.2f)", name, zScore),
			})
		}

		if len(stats.Values) >= 100 {
			q1, q3 := calculateQuartiles(stats.Values)
			iqr := q3 - q1
			lowerBound := q1 - d.config.IQRMultiplier*iqr
			upperBound := q3 + d.config.IQRMultiplier*iqr

			if value < lowerBound || value > upperBound {
				deviation := 0.0
				if value < lowerBound {
					deviation = (lowerBound - value) / iqr
				} else {
					deviation = (value - upperBound) / iqr
				}

				anomalies = append(anomalies, &Anomaly{
					ID:            fmt.Sprintf("iqr-%s-%d", name, time.Now().UnixNano()),
					Timestamp:     fv.Timestamp,
					Type:          AnomalyTypeStatistical,
					Score:         math.Min(100, deviation*30),
					Confidence:    calculateConfidence(stats.Count),
					ContainerID:   fv.ContainerID,
					ContainerName: fv.ContainerName,
					Namespace:     fv.Namespace,
					Feature:       name,
					Value:         value,
					Expected:      (q1 + q3) / 2,
					Deviation:     deviation,
					Description:   fmt.Sprintf("Feature %s outside IQR bounds [%.2f, %.2f]", name, lowerBound, upperBound),
				})
			}
		}
	}

	return anomalies
}

func (d *AIDetector) detectTimeSeriesAnomalies(fv *FeatureVector) []*Anomaly {
	anomalies := make([]*Anomaly, 0)

	d.mu.RLock()
	defer d.mu.RUnlock()

	for name, value := range fv.Features {
		key := fmt.Sprintf("%s:%s", fv.ContainerID, name)
		series, exists := d.timeSeries[key]
		if !exists || len(series) < d.config.TrendWindow {
			continue
		}

		recentPoints := series[len(series)-d.config.TrendWindow:]
		movingAvg := calculateMovingAverage(recentPoints)
		movingStd := calculateMovingStd(recentPoints, movingAvg)

		if movingStd > 0 {
			deviation := (value - movingAvg) / movingStd
			if math.Abs(deviation) > d.config.MADThreshold {
				anomalies = append(anomalies, &Anomaly{
					ID:            fmt.Sprintf("ts-%s-%d", name, time.Now().UnixNano()),
					Timestamp:     fv.Timestamp,
					Type:          AnomalyTypeTimeSeries,
					Score:         math.Min(100, math.Abs(deviation)*25),
					Confidence:    0.8,
					ContainerID:   fv.ContainerID,
					ContainerName: fv.ContainerName,
					Namespace:     fv.Namespace,
					Feature:       name,
					Value:         value,
					Expected:      movingAvg,
					Deviation:     deviation,
					Description:   fmt.Sprintf("Feature %s deviates from moving average (%.2f std)", name, deviation),
				})
			}
		}

		if len(series) >= 10 {
			recentTrend := calculateTrend(series[len(series)-10:])
			if len(series) >= 100 {
				historicalTrend := calculateTrend(series[len(series)-100 : len(series)-10])
				trendChange := math.Abs(recentTrend - historicalTrend)

				if trendChange > 0.5 {
					anomalies = append(anomalies, &Anomaly{
						ID:            fmt.Sprintf("trend-%s-%d", name, time.Now().UnixNano()),
						Timestamp:     fv.Timestamp,
						Type:          AnomalyTypeTimeSeries,
						Score:         math.Min(100, trendChange*50),
						Confidence:    0.7,
						ContainerID:   fv.ContainerID,
						ContainerName: fv.ContainerName,
						Namespace:     fv.Namespace,
						Feature:       name,
						Value:         recentTrend,
						Expected:      historicalTrend,
						Deviation:     trendChange,
						Description:   fmt.Sprintf("Feature %s shows significant trend change", name),
					})
				}
			}
		}
	}

	return anomalies
}

func (d *AIDetector) detectIsolationAnomalies(fv *FeatureVector) []*Anomaly {
	anomalies := make([]*Anomaly, 0)

	if d.isolationForest == nil {
		return anomalies
	}

	score := d.isolationForest.Score(fv.Features)

	if score > d.config.AnomalyThreshold {
		anomalies = append(anomalies, &Anomaly{
			ID:            fmt.Sprintf("if-%d", time.Now().UnixNano()),
			Timestamp:     fv.Timestamp,
			Type:          AnomalyTypeIsolation,
			Score:         score * 100,
			Confidence:    0.85,
			ContainerID:   fv.ContainerID,
			ContainerName: fv.ContainerName,
			Namespace:     fv.Namespace,
			Feature:       "multi-feature",
			Value:         score,
			Expected:      0.5,
			Deviation:     score - 0.5,
			Description:   fmt.Sprintf("Isolation forest score %.2f exceeds threshold", score),
			Context: map[string]interface{}{
				"features":        fv.Features,
				"isolationScore":  score,
				"threshold":       d.config.AnomalyThreshold,
			},
		})
	}

	return anomalies
}

func (d *AIDetector) detectClusteringAnomalies(fv *FeatureVector) []*Anomaly {
	anomalies := make([]*Anomaly, 0)

	d.mu.RLock()
	defer d.mu.RUnlock()

	if len(d.clusters) == 0 {
		return anomalies
	}

	minDistance := math.MaxFloat64
	nearestCluster := -1

	for i, cluster := range d.clusters {
		dist := euclideanDistance(fv.Features, cluster.Centroid)
		if dist < minDistance {
			minDistance = dist
			nearestCluster = i
		}
	}

	if nearestCluster >= 0 {
		cluster := d.clusters[nearestCluster]
		threshold := math.Sqrt(cluster.Variance) * 3

		if minDistance > threshold {
			anomalies = append(anomalies, &Anomaly{
				ID:            fmt.Sprintf("cluster-%d", time.Now().UnixNano()),
				Timestamp:     fv.Timestamp,
				Type:          AnomalyTypeClustering,
				Score:         math.Min(100, (minDistance/threshold)*50),
				Confidence:    0.75,
				ContainerID:   fv.ContainerID,
				ContainerName: fv.ContainerName,
				Namespace:     fv.Namespace,
				Feature:       "multi-feature",
				Value:         minDistance,
				Expected:      threshold,
				Deviation:     minDistance - threshold,
				Description:   fmt.Sprintf("Point is %.2f distance from nearest cluster (threshold: %.2f)", minDistance, threshold),
				Context: map[string]interface{}{
					"nearestCluster": nearestCluster,
					"distance":       minDistance,
					"threshold":      threshold,
				},
			})
		}
	}

	return anomalies
}

func (d *AIDetector) TrainIsolationForest(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	samples := make([]map[string]float64, 0)
	for _, baseline := range d.baselines {
		if !baseline.InLearning && baseline.SampleCount > 0 {
			sample := make(map[string]float64)
			for name, stats := range baseline.Features {
				if stats.Count > 0 {
					sample[name] = stats.Sum / float64(stats.Count)
				}
			}
			if len(sample) > 0 {
				samples = append(samples, sample)
			}
		}
	}

	if len(samples) < d.config.MinSamplesForModel {
		return fmt.Errorf("insufficient samples for training: %d < %d", len(samples), d.config.MinSamplesForModel)
	}

	d.isolationForest = NewIsolationForest(d.config.NumTrees, d.config.SampleSize)
	d.isolationForest.Fit(samples)
	d.lastTrainingAt = time.Now()

	return nil
}

func (d *AIDetector) TrainClusters(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	samples := make([]map[string]float64, 0)
	containerIDs := make([]string, 0)

	for containerID, baseline := range d.baselines {
		if !baseline.InLearning && baseline.SampleCount > 0 {
			sample := make(map[string]float64)
			for name, stats := range baseline.Features {
				if stats.Count > 0 {
					sample[name] = stats.Sum / float64(stats.Count)
				}
			}
			if len(sample) > 0 {
				samples = append(samples, sample)
				containerIDs = append(containerIDs, containerID)
			}
		}
	}

	if len(samples) < d.config.MinClusterSize*2 {
		return fmt.Errorf("insufficient samples for clustering: %d", len(samples))
	}

	k := int(math.Sqrt(float64(len(samples)) / 2))
	if k < 2 {
		k = 2
	}
	if k > 10 {
		k = 10
	}

	d.clusters = kMeansClustering(samples, containerIDs, k, 100)

	return nil
}

func (d *AIDetector) Stats() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	containersLearning := 0
	containersReady := 0
	for _, b := range d.baselines {
		if b.InLearning {
			containersLearning++
		} else {
			containersReady++
		}
	}

	return map[string]interface{}{
		"total_analyzed":      d.totalAnalyzed,
		"anomalies_found":     d.anomaliesFound,
		"containers_learning": containersLearning,
		"containers_ready":    containersReady,
		"clusters":            len(d.clusters),
		"isolation_forest":    d.isolationForest != nil,
		"last_training":       d.lastTrainingAt,
	}
}

func NewIsolationForest(numTrees, sampleSize int) *IsolationForest {
	return &IsolationForest{
		Trees:      make([]*IsolationTree, 0, numTrees),
		NumTrees:   numTrees,
		SampleSize: sampleSize,
	}
}

func (f *IsolationForest) Fit(samples []map[string]float64) {
	if len(samples) == 0 {
		return
	}

	features := make([]string, 0)
	for name := range samples[0] {
		features = append(features, name)
	}

	maxDepth := int(math.Ceil(math.Log2(float64(f.SampleSize))))

	for i := 0; i < f.NumTrees; i++ {
		subsample := bootstrapSample(samples, f.SampleSize)
		tree := &IsolationTree{
			MaxDepth:    maxDepth,
			NumFeatures: len(features),
		}
		tree.Root = buildIsolationTree(subsample, features, 0, maxDepth)
		f.Trees = append(f.Trees, tree)
	}
}

func (f *IsolationForest) Score(sample map[string]float64) float64 {
	if len(f.Trees) == 0 {
		return 0
	}

	totalPathLength := 0.0
	for _, tree := range f.Trees {
		pathLength := tree.PathLength(sample)
		totalPathLength += pathLength
	}

	avgPathLength := totalPathLength / float64(len(f.Trees))
	n := float64(f.SampleSize)
	c := 2*(math.Log(n-1)+0.5772156649) - (2 * (n - 1) / n)
	return math.Pow(2, -avgPathLength/c)
}

func (t *IsolationTree) PathLength(sample map[string]float64) float64 {
	return pathLengthRecursive(t.Root, sample, 0)
}

func pathLengthRecursive(node *IsolationNode, sample map[string]float64, depth int) float64 {
	if node == nil || node.IsLeaf {
		if node != nil && node.Size > 1 {
			n := float64(node.Size)
			return float64(depth) + 2*(math.Log(n-1)+0.5772156649) - (2 * (n - 1) / n)
		}
		return float64(depth)
	}

	value, exists := sample[node.Feature]
	if !exists {
		return float64(depth)
	}

	if value < node.SplitValue {
		return pathLengthRecursive(node.Left, sample, depth+1)
	}
	return pathLengthRecursive(node.Right, sample, depth+1)
}

func buildIsolationTree(samples []map[string]float64, features []string, depth, maxDepth int) *IsolationNode {
	if len(samples) <= 1 || depth >= maxDepth {
		return &IsolationNode{
			IsLeaf: true,
			Size:   len(samples),
		}
	}

	featureIdx := randomInt(len(features))
	feature := features[featureIdx]
	min, max := math.MaxFloat64, -math.MaxFloat64
	for _, sample := range samples {
		if v, exists := sample[feature]; exists {
			if v < min {
				min = v
			}
			if v > max {
				max = v
			}
		}
	}

	if min == max {
		return &IsolationNode{
			IsLeaf: true,
			Size:   len(samples),
		}
	}

	splitValue := min + randomFloat()*(max-min)
	var left, right []map[string]float64
	for _, sample := range samples {
		if v, exists := sample[feature]; exists && v < splitValue {
			left = append(left, sample)
		} else {
			right = append(right, sample)
		}
	}

	return &IsolationNode{
		Feature:    feature,
		SplitValue: splitValue,
		Left:       buildIsolationTree(left, features, depth+1, maxDepth),
		Right:      buildIsolationTree(right, features, depth+1, maxDepth),
	}
}

func calculateConfidence(sampleCount int) float64 {
	return 1.0 - math.Exp(-float64(sampleCount)/100)
}

func calculateQuartiles(values []float64) (q1, q3 float64) {
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	n := len(sorted)
	q1 = sorted[n/4]
	q3 = sorted[3*n/4]
	return
}

func calculateMovingAverage(points []*TimeSeriesPoint) float64 {
	if len(points) == 0 {
		return 0
	}
	sum := 0.0
	for _, p := range points {
		sum += p.Value
	}
	return sum / float64(len(points))
}

func calculateMovingStd(points []*TimeSeriesPoint, mean float64) float64 {
	if len(points) < 2 {
		return 0
	}
	sumSq := 0.0
	for _, p := range points {
		diff := p.Value - mean
		sumSq += diff * diff
	}
	return math.Sqrt(sumSq / float64(len(points)-1))
}

func calculateTrend(series []*TimeSeriesPoint) float64 {
	if len(series) < 2 {
		return 0
	}

	n := float64(len(series))
	sumX, sumY, sumXY, sumXX := 0.0, 0.0, 0.0, 0.0

	for i, p := range series {
		x := float64(i)
		sumX += x
		sumY += p.Value
		sumXY += x * p.Value
		sumXX += x * x
	}

	denominator := n*sumXX - sumX*sumX
	if denominator == 0 {
		return 0
	}

	return (n*sumXY - sumX*sumY) / denominator
}

func euclideanDistance(a, b map[string]float64) float64 {
	sumSq := 0.0
	for key, va := range a {
		vb := b[key]
		diff := va - vb
		sumSq += diff * diff
	}
	return math.Sqrt(sumSq)
}

func kMeansClustering(samples []map[string]float64, containerIDs []string, k, maxIter int) []*Cluster {
	if len(samples) < k {
		return nil
	}

	clusters := make([]*Cluster, k)
	for i := 0; i < k; i++ {
		idx := randomInt(len(samples))
		centroid := make(map[string]float64)
		for key, val := range samples[idx] {
			centroid[key] = val
		}
		clusters[i] = &Cluster{
			ID:        i,
			Centroid:  centroid,
			Members:   make([]string, 0),
			CreatedAt: time.Now(),
		}
	}

	for iter := 0; iter < maxIter; iter++ {
		for _, c := range clusters {
			c.Members = make([]string, 0)
		}

		for i, sample := range samples {
			minDist := math.MaxFloat64
			nearest := 0
			for j, cluster := range clusters {
				dist := euclideanDistance(sample, cluster.Centroid)
				if dist < minDist {
					minDist = dist
					nearest = j
				}
			}
			clusters[nearest].Members = append(clusters[nearest].Members, containerIDs[i])
		}

		for _, cluster := range clusters {
			if len(cluster.Members) == 0 {
				continue
			}

			newCentroid := make(map[string]float64)
			for _, memberID := range cluster.Members {
				for i, cid := range containerIDs {
					if cid == memberID {
						for key, val := range samples[i] {
							newCentroid[key] += val
						}
						break
					}
				}
			}

			for key := range newCentroid {
				newCentroid[key] /= float64(len(cluster.Members))
			}
			cluster.Centroid = newCentroid
		}
	}

	for _, cluster := range clusters {
		if len(cluster.Members) < 2 {
			continue
		}

		totalDist := 0.0
		for _, memberID := range cluster.Members {
			for i, cid := range containerIDs {
				if cid == memberID {
					dist := euclideanDistance(samples[i], cluster.Centroid)
					totalDist += dist * dist
					break
				}
			}
		}
		cluster.Variance = totalDist / float64(len(cluster.Members))
	}

	return clusters
}

func bootstrapSample(samples []map[string]float64, size int) []map[string]float64 {
	result := make([]map[string]float64, 0, size)
	for i := 0; i < size && i < len(samples); i++ {
		idx := randomInt(len(samples))
		result = append(result, samples[idx])
	}
	return result
}

var rngMu sync.Mutex
var rngState uint64 = uint64(time.Now().UnixNano())

func randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	rngMu.Lock()
	rngState = rngState*6364136223846793005 + 1442695040888963407
	result := int(uint(rngState>>33) % uint(max))
	rngMu.Unlock()
	return result
}

func randomFloat() float64 {
	rngMu.Lock()
	rngState = rngState*6364136223846793005 + 1442695040888963407
	result := float64(rngState>>33) / float64(1<<31)
	rngMu.Unlock()
	return result
}
