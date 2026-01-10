package drift

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ExecutableInfo tracks an executable's baseline information.
type ExecutableInfo struct {
	Path      string    `json:"path"`
	Hash      string    `json:"hash"`
	Size      int64     `json:"size"`
	Mode      os.FileMode `json:"mode"`
	FirstSeen time.Time `json:"firstSeen"`
}

// ContainerBaseline represents the known-good state of a container.
type ContainerBaseline struct {
	ContainerID   string                     `json:"containerId"`
	ImageID       string                     `json:"imageId"`
	ImageName     string                     `json:"imageName"`
	CreatedAt     time.Time                  `json:"createdAt"`
	Executables   map[string]*ExecutableInfo `json:"executables"`
	LearnedAt     time.Time                  `json:"learnedAt"`
	LearningMode  bool                       `json:"learningMode"`
}

// DriftEvent represents a detected drift from baseline.
type DriftEvent struct {
	ContainerID   string    `json:"containerId"`
	ContainerName string    `json:"containerName"`
	ImageName     string    `json:"imageName"`
	EventType     string    `json:"eventType"` // "new_executable", "modified_executable", "deleted_executable"
	Path          string    `json:"path"`
	OldHash       string    `json:"oldHash,omitempty"`
	NewHash       string    `json:"newHash,omitempty"`
	DetectedAt    time.Time `json:"detectedAt"`
	Severity      string    `json:"severity"`
	MITRETechnique string   `json:"mitreTechnique"`
}

// DriftDetector monitors containers for drift from their original image.
type DriftDetector struct {
	baselines      map[string]*ContainerBaseline
	mu             sync.RWMutex
	learningPeriod time.Duration
	blockDrift     bool
	eventChan      chan *DriftEvent

	// Callbacks
	onDriftDetected func(*DriftEvent)
}

// NewDriftDetector creates a new drift detector.
func NewDriftDetector(learningPeriod time.Duration, blockDrift bool) *DriftDetector {
	return &DriftDetector{
		baselines:      make(map[string]*ContainerBaseline),
		learningPeriod: learningPeriod,
		blockDrift:     blockDrift,
		eventChan:      make(chan *DriftEvent, 100),
	}
}

// SetDriftCallback sets the callback for drift events.
func (d *DriftDetector) SetDriftCallback(callback func(*DriftEvent)) {
	d.onDriftDetected = callback
}

// Events returns the channel for drift events.
func (d *DriftDetector) Events() <-chan *DriftEvent {
	return d.eventChan
}

// RegisterContainer creates a baseline for a new container.
func (d *DriftDetector) RegisterContainer(containerID, imageID, imageName string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.baselines[containerID]; exists {
		return nil // Already registered
	}

	baseline := &ContainerBaseline{
		ContainerID:  containerID,
		ImageID:      imageID,
		ImageName:    imageName,
		CreatedAt:    time.Now(),
		Executables:  make(map[string]*ExecutableInfo),
		LearningMode: true,
	}

	d.baselines[containerID] = baseline
	fmt.Printf("[Drift] Registered container %s (image: %s), learning mode enabled\n", containerID[:12], imageName)

	// Schedule end of learning period
	go func() {
		time.Sleep(d.learningPeriod)
		d.mu.Lock()
		if b, ok := d.baselines[containerID]; ok {
			b.LearningMode = false
			b.LearnedAt = time.Now()
			fmt.Printf("[Drift] Container %s learning complete, %d executables baselined\n",
				containerID[:12], len(b.Executables))
		}
		d.mu.Unlock()
	}()

	return nil
}

// UnregisterContainer removes a container from tracking.
func (d *DriftDetector) UnregisterContainer(containerID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.baselines, containerID)
}

// CheckExecutable checks if an executable matches the baseline.
func (d *DriftDetector) CheckExecutable(containerID, path string, info os.FileInfo) (*DriftEvent, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	baseline, exists := d.baselines[containerID]
	if !exists {
		return nil, nil // Container not tracked
	}

	// Calculate hash of executable
	hash, err := hashFile(path)
	if err != nil {
		return nil, err
	}

	execInfo := &ExecutableInfo{
		Path:      path,
		Hash:      hash,
		Size:      info.Size(),
		Mode:      info.Mode(),
		FirstSeen: time.Now(),
	}

	// During learning mode, just record executables
	if baseline.LearningMode {
		baseline.Executables[path] = execInfo
		return nil, nil
	}

	// Check against baseline
	baselineExec, known := baseline.Executables[path]

	if !known {
		// New executable not in baseline - DRIFT DETECTED
		event := &DriftEvent{
			ContainerID:    containerID,
			ImageName:      baseline.ImageName,
			EventType:      "new_executable",
			Path:           path,
			NewHash:        hash,
			DetectedAt:     time.Now(),
			Severity:       "critical",
			MITRETechnique: "T1059.004", // Command and Scripting Interpreter
		}

		d.emitEvent(event)
		return event, nil
	}

	if baselineExec.Hash != hash {
		// Executable modified - DRIFT DETECTED
		event := &DriftEvent{
			ContainerID:    containerID,
			ImageName:      baseline.ImageName,
			EventType:      "modified_executable",
			Path:           path,
			OldHash:        baselineExec.Hash,
			NewHash:        hash,
			DetectedAt:     time.Now(),
			Severity:       "critical",
			MITRETechnique: "T1036", // Masquerading
		}

		d.emitEvent(event)
		return event, nil
	}

	return nil, nil // No drift
}

// ProcessExecEvent handles a process execution event from CDR.
func (d *DriftDetector) ProcessExecEvent(containerID, containerName, imageName, execPath string) *DriftEvent {
	d.mu.Lock()
	defer d.mu.Unlock()

	baseline, exists := d.baselines[containerID]
	if !exists {
		// Auto-register unknown container
		baseline = &ContainerBaseline{
			ContainerID:  containerID,
			ImageName:    imageName,
			CreatedAt:    time.Now(),
			Executables:  make(map[string]*ExecutableInfo),
			LearningMode: true,
		}
		d.baselines[containerID] = baseline

		// Start learning
		go func() {
			time.Sleep(d.learningPeriod)
			d.mu.Lock()
			if b, ok := d.baselines[containerID]; ok {
				b.LearningMode = false
				b.LearnedAt = time.Now()
			}
			d.mu.Unlock()
		}()
	}

	// During learning mode, record the executable
	if baseline.LearningMode {
		if _, known := baseline.Executables[execPath]; !known {
			baseline.Executables[execPath] = &ExecutableInfo{
				Path:      execPath,
				FirstSeen: time.Now(),
			}
		}
		return nil
	}

	// After learning, check for drift
	if _, known := baseline.Executables[execPath]; !known {
		event := &DriftEvent{
			ContainerID:    containerID,
			ContainerName:  containerName,
			ImageName:      imageName,
			EventType:      "new_executable",
			Path:           execPath,
			DetectedAt:     time.Now(),
			Severity:       "critical",
			MITRETechnique: "T1059.004",
		}

		d.emitEvent(event)
		return event
	}

	return nil
}

// GetBaseline returns the baseline for a container.
func (d *DriftDetector) GetBaseline(containerID string) *ContainerBaseline {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.baselines[containerID]
}

// GetAllBaselines returns all tracked baselines.
func (d *DriftDetector) GetAllBaselines() map[string]*ContainerBaseline {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make(map[string]*ContainerBaseline)
	for k, v := range d.baselines {
		result[k] = v
	}
	return result
}

// Stats returns drift detector statistics.
func (d *DriftDetector) Stats() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	learning := 0
	monitoring := 0
	totalExecutables := 0

	for _, b := range d.baselines {
		if b.LearningMode {
			learning++
		} else {
			monitoring++
		}
		totalExecutables += len(b.Executables)
	}

	return map[string]interface{}{
		"containers_learning":   learning,
		"containers_monitoring": monitoring,
		"total_executables":     totalExecutables,
		"block_drift":           d.blockDrift,
		"learning_period":       d.learningPeriod.String(),
	}
}

func (d *DriftDetector) emitEvent(event *DriftEvent) {
	select {
	case d.eventChan <- event:
	default:
		fmt.Printf("[Drift] Event channel full, dropping event\n")
	}

	if d.onDriftDetected != nil {
		go d.onDriftDetected(event)
	}
}

func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// ScanContainerFilesystem scans a container's filesystem for executables.
func ScanContainerFilesystem(rootfs string) (map[string]*ExecutableInfo, error) {
	executables := make(map[string]*ExecutableInfo)

	execDirs := []string{
		"/bin", "/sbin", "/usr/bin", "/usr/sbin",
		"/usr/local/bin", "/usr/local/sbin",
	}

	for _, dir := range execDirs {
		fullPath := filepath.Join(rootfs, dir)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			continue
		}

		filepath.Walk(fullPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			// Check if executable
			if info.Mode()&0111 != 0 {
				hash, _ := hashFile(path)
				relPath := path[len(rootfs):]
				executables[relPath] = &ExecutableInfo{
					Path:      relPath,
					Hash:      hash,
					Size:      info.Size(),
					Mode:      info.Mode(),
					FirstSeen: time.Now(),
				}
			}
			return nil
		})
	}

	return executables, nil
}
