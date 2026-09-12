package metadata

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/http"
	"strings"
	"testing"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

// buildTestTIFF constructs a minimal valid little-endian TIFF block with EXIF and GPS tags.
func buildTestTIFF(includeGPS bool) []byte {
	buf := new(bytes.Buffer)

	// 1. TIFF Header (8 bytes)
	buf.Write([]byte{'I', 'I'}) // Little endian
	_ = binary.Write(buf, binary.LittleEndian, uint16(42))
	_ = binary.Write(buf, binary.LittleEndian, uint32(8)) // IFD0 at offset 8

	// Layout planning:
	// Offset 8: IFD0
	//   2 bytes numEntries
	//   N * 12 bytes entries
	//   4 bytes next IFD (0)
	// Followed by string values and sub-IFD (GPS)

	var entriesCount uint16 = 4
	if includeGPS {
		entriesCount = 5
	}

	// Calculate base offsets
	ifd0Size := 2 + int(entriesCount)*12 + 4
	valOffset := 8 + ifd0Size

	makeStr := "TestCameraCo\x00"
	modelStr := "Model X100\x00"
	softStr := "EditSoft 2.0\x00"
	dateStr := "2023:08:20 15:30:00\x00"

	makeOffset := valOffset
	modelOffset := makeOffset + len(makeStr)
	softOffset := modelOffset + len(modelStr)
	dateOffset := softOffset + len(softStr)
	gpsIFDOffset := dateOffset + len(dateStr)

	_ = binary.Write(buf, binary.LittleEndian, entriesCount)

	// Entry 1: Make (0x010F, ASCII=2)
	_ = binary.Write(buf, binary.LittleEndian, uint16(0x010F))
	_ = binary.Write(buf, binary.LittleEndian, uint16(2))
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(makeStr)))
	_ = binary.Write(buf, binary.LittleEndian, uint32(makeOffset))

	// Entry 2: Model (0x0110, ASCII=2)
	_ = binary.Write(buf, binary.LittleEndian, uint16(0x0110))
	_ = binary.Write(buf, binary.LittleEndian, uint16(2))
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(modelStr)))
	_ = binary.Write(buf, binary.LittleEndian, uint32(modelOffset))

	// Entry 3: Software (0x0131, ASCII=2)
	_ = binary.Write(buf, binary.LittleEndian, uint16(0x0131))
	_ = binary.Write(buf, binary.LittleEndian, uint16(2))
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(softStr)))
	_ = binary.Write(buf, binary.LittleEndian, uint32(softOffset))

	// Entry 4: DateTime (0x0132, ASCII=2)
	_ = binary.Write(buf, binary.LittleEndian, uint16(0x0132))
	_ = binary.Write(buf, binary.LittleEndian, uint16(2))
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(dateStr)))
	_ = binary.Write(buf, binary.LittleEndian, uint32(dateOffset))

	if includeGPS {
		// Entry 5: GPSInfo (0x8825, LONG=4, count=1)
		_ = binary.Write(buf, binary.LittleEndian, uint16(0x8825))
		_ = binary.Write(buf, binary.LittleEndian, uint16(4))
		_ = binary.Write(buf, binary.LittleEndian, uint32(1))
		_ = binary.Write(buf, binary.LittleEndian, uint32(gpsIFDOffset))
	}

	_ = binary.Write(buf, binary.LittleEndian, uint32(0)) // next IFD

	// Write string values
	buf.WriteString(makeStr)
	buf.WriteString(modelStr)
	buf.WriteString(softStr)
	buf.WriteString(dateStr)

	if includeGPS {
		// Write GPS IFD:
		// 4 entries: LatRef (0x0001), Lat (0x0002), LonRef (0x0003), Lon (0x0004)
		var gpsCount uint16 = 4
		gpsDataOffset := gpsIFDOffset + 2 + int(gpsCount)*12 + 4

		_ = binary.Write(buf, binary.LittleEndian, gpsCount)

		// 1. LatRef: "N\x00" (inline <= 4 bytes)
		_ = binary.Write(buf, binary.LittleEndian, uint16(0x0001))
		_ = binary.Write(buf, binary.LittleEndian, uint16(2))
		_ = binary.Write(buf, binary.LittleEndian, uint32(2))
		buf.Write([]byte{'N', 0, 0, 0})

		// 2. Lat: 3 rationals (24 bytes) at gpsDataOffset
		latOffset := gpsDataOffset
		lonOffset := latOffset + 24
		_ = binary.Write(buf, binary.LittleEndian, uint16(0x0002))
		_ = binary.Write(buf, binary.LittleEndian, uint16(5)) // RATIONAL
		_ = binary.Write(buf, binary.LittleEndian, uint32(3))
		_ = binary.Write(buf, binary.LittleEndian, uint32(latOffset))

		// 3. LonRef: "W\x00"
		_ = binary.Write(buf, binary.LittleEndian, uint16(0x0003))
		_ = binary.Write(buf, binary.LittleEndian, uint16(2))
		_ = binary.Write(buf, binary.LittleEndian, uint32(2))
		buf.Write([]byte{'W', 0, 0, 0})

		// 4. Lon: 3 rationals (24 bytes) at lonOffset
		_ = binary.Write(buf, binary.LittleEndian, uint16(0x0004))
		_ = binary.Write(buf, binary.LittleEndian, uint16(5))
		_ = binary.Write(buf, binary.LittleEndian, uint32(3))
		_ = binary.Write(buf, binary.LittleEndian, uint32(lonOffset))

		_ = binary.Write(buf, binary.LittleEndian, uint32(0)) // next IFD

		// Write Lat: 37 deg, 46 min, 30 sec (37.775 N)
		_ = binary.Write(buf, binary.LittleEndian, uint32(37))
		_ = binary.Write(buf, binary.LittleEndian, uint32(1))
		_ = binary.Write(buf, binary.LittleEndian, uint32(46))
		_ = binary.Write(buf, binary.LittleEndian, uint32(1))
		_ = binary.Write(buf, binary.LittleEndian, uint32(30))
		_ = binary.Write(buf, binary.LittleEndian, uint32(1))

		// Write Lon: 122 deg, 25 min, 12 sec (-122.42 W)
		_ = binary.Write(buf, binary.LittleEndian, uint32(122))
		_ = binary.Write(buf, binary.LittleEndian, uint32(1))
		_ = binary.Write(buf, binary.LittleEndian, uint32(25))
		_ = binary.Write(buf, binary.LittleEndian, uint32(1))
		_ = binary.Write(buf, binary.LittleEndian, uint32(12))
		_ = binary.Write(buf, binary.LittleEndian, uint32(1))
	}

	return buf.Bytes()
}

// buildTestJPEG wraps TIFF bytes inside a valid JPEG APP1 segment
func buildTestJPEG(tiffData []byte) []byte {
	buf := new(bytes.Buffer)
	buf.Write([]byte{0xFF, 0xD8}) // SOI

	// APP1
	buf.Write([]byte{0xFF, 0xE1})
	segPayload := append([]byte("Exif\x00\x00"), tiffData...)
	segLen := uint16(len(segPayload) + 2)
	_ = binary.Write(buf, binary.BigEndian, segLen)
	buf.Write(segPayload)

	// EOI
	buf.Write([]byte{0xFF, 0xD9})
	return buf.Bytes()
}

func TestMetadataAnalyzer_DirectImageWithGPS(t *testing.T) {
	ctx := context.Background()
	a := New()
	target := model.Target{Onion: "testservice.onion"}

	tiffData := buildTestTIFF(true)
	jpegBytes := buildTestJPEG(tiffData)

	page := model.Page{
		URL:        "http://testservice.onion/uploads/photo.jpg",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "image/jpeg"},
		Body:       jpegBytes,
	}

	findings, err := a.Analyze(ctx, target, page)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "OPSEC-003" {
		t.Errorf("expected ID OPSEC-003, got %s", f.ID)
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("expected severity HIGH for GPS leak, got %s", f.Severity)
	}

	descText := ""
	for _, ev := range f.Evidence {
		descText += ev.Description + " "
	}

	if !strings.Contains(descText, "37.775000") || !strings.Contains(descText, "-122.420000") {
		t.Errorf("expected GPS coordinates in evidence, got: %s", descText)
	}
	if !strings.Contains(descText, "TestCameraCo") {
		t.Errorf("expected camera make in evidence, got: %s", descText)
	}
	if !strings.Contains(descText, "EditSoft 2.0") {
		t.Errorf("expected software in evidence, got: %s", descText)
	}
}

func TestMetadataAnalyzer_DirectImageWithoutGPS(t *testing.T) {
	ctx := context.Background()
	a := New()
	target := model.Target{Onion: "testservice.onion"}

	tiffData := buildTestTIFF(false)
	jpegBytes := buildTestJPEG(tiffData)

	page := model.Page{
		URL:        "http://testservice.onion/uploads/camera.jpg",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "image/jpeg"},
		Body:       jpegBytes,
	}

	findings, err := a.Analyze(ctx, target, page)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != model.SeverityLow {
		t.Errorf("expected severity LOW without GPS, got %s", f.Severity)
	}
}

func TestMetadataAnalyzer_HTMLPageReferencesImage(t *testing.T) {
	ctx := context.Background()
	a := New()
	target := model.Target{Onion: "testservice.onion"}

	tiffData := buildTestTIFF(true)
	jpegBytes := buildTestJPEG(tiffData)

	// Mock Fetch
	a.Fetch = func(ctx context.Context, targetURL string) ([]byte, int, error) {
		if targetURL == "http://testservice.onion/static/user_pic.jpg" {
			return jpegBytes, http.StatusOK, nil
		}
		return nil, http.StatusNotFound, nil
	}

	html := `
<html>
<head><title>Profile</title></head>
<body>
  <h1>User Profile</h1>
  <img src="/static/user_pic.jpg" alt="profile picture">
</body>
</html>`

	page := model.Page{
		URL:        "http://testservice.onion/profile",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
		Body:       []byte(html),
	}

	findings, err := a.Analyze(ctx, target, page)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from referenced image, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "OPSEC-003" {
		t.Errorf("expected ID OPSEC-003, got %s", f.ID)
	}
}

func TestMetadataAnalyzer_TrueNegatives(t *testing.T) {
	ctx := context.Background()
	a := New()
	target := model.Target{Onion: "testservice.onion"}

	// Plain JPEG without APP1 EXIF segment
	cleanJPEG := []byte{0xFF, 0xD8, 0xFF, 0xD9}

	page := model.Page{
		URL:        "http://testservice.onion/clean.jpg",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "image/jpeg"},
		Body:       cleanJPEG,
	}

	findings, err := a.Analyze(ctx, target, page)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean image, got %d", len(findings))
	}

	// Clean HTML without images
	cleanHTML := `<html><body><p>Hello, OnionSec!</p></body></html>`
	pageHTML := model.Page{
		URL:        "http://testservice.onion/index.html",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html"},
		Body:       []byte(cleanHTML),
	}

	findings2, err := a.Analyze(ctx, target, pageHTML)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(findings2) != 0 {
		t.Errorf("expected 0 findings for clean HTML, got %d", len(findings2))
	}
}
