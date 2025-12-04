package audio

import (
	"bytes"
	_ "embed"
	"io"
	"sync"
	"time"

	"github.com/gopxl/beep/v2"
	"github.com/gopxl/beep/v2/effects"
	"github.com/gopxl/beep/v2/mp3"
	"github.com/gopxl/beep/v2/speaker"
	"github.com/gopxl/beep/v2/wav"
)

//go:embed assets/max_points_achieved.mp3
var maxPointsAchievedMP3 []byte

//go:embed assets/points_gained.mp3
var pointsGainedMP3 []byte

//go:embed assets/gain.wav
var officialGainWAV []byte

var (
	initialized   bool
	initMu        sync.Mutex
	sampleRate    beep.SampleRate
	
	// Cached decoded sounds for faster playback
	pointsGainedBuffer *beep.Buffer
	maxPointsBuffer    *beep.Buffer
	
	// Volume multiplier (2.0 = 2x louder, 3.0 = 3x louder)
	volumeGain = 2.5
	
	// Sound settings (set via SetOptions before Init)
	soundDisabled      bool
	noRepeatSound      bool
	useOfficialSound   bool // Use official CyberPatriot gain.wav instead of custom mp3
)

// SetOptions configures audio settings. Call before Init().
func SetOptions(noSound, noRepeat, official bool) {
	initMu.Lock()
	defer initMu.Unlock()
	soundDisabled = noSound
	noRepeatSound = noRepeat
	useOfficialSound = official
}

// Init initializes the audio system. Call this once at startup.
func Init() error {
	initMu.Lock()
	defer initMu.Unlock()
	
	if initialized {
		return nil
	}
	
	// If sounds are disabled, mark as initialized but don't load anything
	if soundDisabled {
		initialized = true
		return nil
	}
	
	// Decode points_gained sound - use official WAV or custom MP3
	var streamer beep.StreamSeekCloser
	var format beep.Format
	var err error
	
	if useOfficialSound {
		reader := io.NopCloser(bytes.NewReader(officialGainWAV))
		streamer, format, err = wav.Decode(reader)
	} else {
		reader := io.NopCloser(bytes.NewReader(pointsGainedMP3))
		streamer, format, err = mp3.Decode(reader)
	}
	if err != nil {
		return err
	}
	
	sampleRate = format.SampleRate
	
	// Initialize speaker
	err = speaker.Init(sampleRate, sampleRate.N(time.Second/10))
	if err != nil {
		streamer.Close()
		return err
	}
	
	// Buffer the points_gained sound for fast repeated playback
	pointsGainedBuffer = beep.NewBuffer(format)
	pointsGainedBuffer.Append(streamer)
	streamer.Close()
	
	// Buffer the max_points sound
	reader2 := io.NopCloser(bytes.NewReader(maxPointsAchievedMP3))
	streamer2, _, err := mp3.Decode(reader2)
	if err != nil {
		return err
	}
	maxPointsBuffer = beep.NewBuffer(format)
	maxPointsBuffer.Append(streamer2)
	streamer2.Close()
	
	initialized = true
	return nil
}

// amplify wraps a streamer with volume gain.
func amplify(s beep.Streamer) beep.Streamer {
	return &effects.Gain{
		Streamer: s,
		Gain:     volumeGain,
	}
}

// PlayPointsGained plays the points gained sound once.
func PlayPointsGained() {
	if !initialized || soundDisabled || pointsGainedBuffer == nil {
		return
	}
	
	streamer := pointsGainedBuffer.Streamer(0, pointsGainedBuffer.Len())
	speaker.Play(amplify(streamer))
}

// PlayPointsGainedMultiple plays the points gained sound N times with a short delay.
// This creates the satisfying "ding ding ding" effect for multiple vulns found.
// If noRepeatSound is set, plays only once regardless of count.
func PlayPointsGainedMultiple(count int) {
	if !initialized || soundDisabled || pointsGainedBuffer == nil || count <= 0 {
		return
	}
	
	// If no-repeat mode, just play once
	if noRepeatSound {
		PlayPointsGained()
		return
	}
	
	// Cap at 20 to avoid excessive noise
	if count > 20 {
		count = 20
	}
	
	go func() {
		for i := 0; i < count; i++ {
			streamer := pointsGainedBuffer.Streamer(0, pointsGainedBuffer.Len())
			done := make(chan struct{})
			speaker.Play(beep.Seq(amplify(streamer), beep.Callback(func() {
				close(done)
			})))
			<-done
			
			// Small delay between dings (100ms)
			if i < count-1 {
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
}

// PlayMaxPointsAchieved plays the victory sound for 100/100.
func PlayMaxPointsAchieved() {
	if !initialized || soundDisabled || maxPointsBuffer == nil {
		return
	}
	
	streamer := maxPointsBuffer.Streamer(0, maxPointsBuffer.Len())
	speaker.Play(amplify(streamer))
}

// IsInitialized returns true if audio is ready.
func IsInitialized() bool {
	initMu.Lock()
	defer initMu.Unlock()
	return initialized
}

