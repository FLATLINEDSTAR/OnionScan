// Package metadata inspects images referenced or served by the onion service
// for EXIF, camera, software, timestamp, and GPS geolocation metadata (OPSEC-003).
//
// Safety rule: this analyzer parses image binary metadata safely using standard library
// bounded readers and strict bounds checks, respecting crawler size limits.
package metadata

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/AryanXCode646/OnionScan/internal/model"
)

var (
	imgSrcRe = regexp.MustCompile(`(?i)<img[^>]+src=["']([^"'#\s>]+)["']`)
)

const (
	maxImageBytes = 5 * 1024 * 1024 // 5MB per crawler limit
	maxImagesPage = 5               // max images fetched per page
)

// Metadata contains parsed image metadata fields.
type Metadata struct {
	Make      string
	Model     string
	Software  string
	DateTime  string
	Artist    string
	LensModel string
	HasGPS    bool
	Latitude  float64
	Longitude float64
	Altitude  *float64
}

type Analyzer struct {
	// Fetch allows injecting custom fetchers for Tor or tests.
	Fetch func(ctx context.Context, targetURL string) ([]byte, int, error)

	visitedMu sync.Mutex
	visited   map[string]bool
}

func New() *Analyzer {
	return &Analyzer{
		Fetch:   defaultFetch,
		visited: make(map[string]bool),
	}
}

// NewWithClient returns a metadata analyzer that fetches images via the provided HTTP client.
func NewWithClient(client *http.Client) *Analyzer {
	if client == nil {
		return New()
	}
	return &Analyzer{
		Fetch: func(ctx context.Context, targetURL string) ([]byte, int, error) {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
			if err != nil {
				return nil, 0, err
			}
			req.Header.Set("User-Agent", "OnionSec/0.1 (+authorized-scan)")

			resp, err := client.Do(req)
			if err != nil {
				return nil, 0, err
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(io.LimitReader(resp.Body, maxImageBytes))
			if err != nil {
				return nil, resp.StatusCode, err
			}
			return body, resp.StatusCode, nil
		},
		visited: make(map[string]bool),
	}
}

// NewWithFetch returns a metadata analyzer with a custom fetch function.
func NewWithFetch(fetch func(ctx context.Context, targetURL string) ([]byte, int, error)) *Analyzer {
	if fetch == nil {
		fetch = defaultFetch
	}
	return &Analyzer{
		Fetch:   fetch,
		visited: make(map[string]bool),
	}
}

func (a *Analyzer) Name() string { return "metadata" }

func (a *Analyzer) Analyze(ctx context.Context, target model.Target, page model.Page) ([]model.Finding, error) {
	var evidence []model.Evidence
	hasGPSOverall := false

	// Helper to analyze image bytes
	inspectImage := func(data []byte, imgURL string) {
		meta, err := ParseImage(data)
		if err != nil || meta == nil {
			return
		}
		evs := meta.ToEvidence(imgURL)
		if len(evs) > 0 {
			evidence = append(evidence, evs...)
			if meta.HasGPS {
				hasGPSOverall = true
			}
		}
	}

	// 1. If page itself is an image
	if isImage(page.Headers, page.URL, page.Body) {
		inspectImage(page.Body, page.URL)
	}

	// 2. If page is HTML, find image references and inspect them
	if isHTML(page.Headers) && a.Fetch != nil {
		pageURL, err := url.Parse(page.URL)
		if err == nil {
			matches := imgSrcRe.FindAllStringSubmatch(string(page.Body), -1)
			fetchedCount := 0
			for _, m := range matches {
				if fetchedCount >= maxImagesPage {
					break
				}
				if len(m) < 2 {
					continue
				}
				src := strings.TrimSpace(m[1])
				if src == "" || strings.HasPrefix(src, "data:") {
					continue
				}

				absURL, ok := resolveSameOrigin(pageURL, src, target.Onion)
				if !ok {
					continue
				}

				a.visitedMu.Lock()
				if a.visited == nil {
					a.visited = make(map[string]bool)
				}
				alreadySeen := a.visited[absURL]
				if !alreadySeen {
					a.visited[absURL] = true
				}
				a.visitedMu.Unlock()

				if alreadySeen {
					continue
				}

				fetchedCount++
				data, code, err := a.Fetch(ctx, absURL)
				if err == nil && code == http.StatusOK && len(data) > 0 {
					inspectImage(data, absURL)
				}
			}
		}
	}

	evidence = dedupeEvidence(evidence)
	if len(evidence) == 0 {
		return nil, nil
	}

	severity := model.SeverityLow
	if hasGPSOverall {
		severity = model.SeverityHigh
	}

	finding := model.Finding{
		ID:             "OPSEC-003",
		Title:          "Public EXIF metadata in uploaded images",
		Severity:       severity,
		Confidence:     0.95,
		Target:         target.Onion,
		Analyzer:       a.Name(),
		Evidence:       evidence,
		Explanation:    "Publicly accessible images on the service contain embedded EXIF metadata (such as GPS coordinates, camera hardware identifiers, timestamps, or editing software). This data can reveal the physical location of the operator or link content to real-world devices.",
		Recommendation: "Configure image processing pipelines to strip all EXIF metadata before storing or serving user-uploaded images.",
		CreatedAt:      time.Now(),
	}

	return []model.Finding{finding}, nil
}

// ToEvidence converts Metadata fields into model.Evidence.
func (m *Metadata) ToEvidence(sourceURL string) []model.Evidence {
	var ev []model.Evidence
	if m.HasGPS {
		ev = append(ev, model.Evidence{
			Type:        model.EvidenceMetadata,
			Description: fmt.Sprintf("GPS coordinates: %.6f, %.6f (image: %s)", m.Latitude, m.Longitude, sourceURL),
			Source:      sourceURL,
		})
		if m.Altitude != nil {
			ev = append(ev, model.Evidence{
				Type:        model.EvidenceMetadata,
				Description: fmt.Sprintf("GPS altitude: %.1fm (image: %s)", *m.Altitude, sourceURL),
				Source:      sourceURL,
			})
		}
	}
	if m.Make != "" || m.Model != "" {
		camera := strings.TrimSpace(m.Make + " " + m.Model)
		ev = append(ev, model.Evidence{
			Type:        model.EvidenceMetadata,
			Description: fmt.Sprintf("Camera hardware: %s (image: %s)", camera, sourceURL),
			Source:      sourceURL,
		})
	}
	if m.Software != "" {
		ev = append(ev, model.Evidence{
			Type:        model.EvidenceMetadata,
			Description: fmt.Sprintf("Image software: %s (image: %s)", m.Software, sourceURL),
			Source:      sourceURL,
		})
	}
	if m.DateTime != "" {
		ev = append(ev, model.Evidence{
			Type:        model.EvidenceMetadata,
			Description: fmt.Sprintf("Capture timestamp: %s (image: %s)", m.DateTime, sourceURL),
			Source:      sourceURL,
		})
	}
	if m.Artist != "" {
		ev = append(ev, model.Evidence{
			Type:        model.EvidenceMetadata,
			Description: fmt.Sprintf("Author/Artist: %s (image: %s)", m.Artist, sourceURL),
			Source:      sourceURL,
		})
	}
	if m.LensModel != "" {
		ev = append(ev, model.Evidence{
			Type:        model.EvidenceMetadata,
			Description: fmt.Sprintf("Lens model: %s (image: %s)", m.LensModel, sourceURL),
			Source:      sourceURL,
		})
	}
	return ev
}

// ParseImage attempts to extract EXIF metadata from raw image bytes.
func ParseImage(data []byte) (*Metadata, error) {
	if len(data) < 8 {
		return nil, nil
	}

	// 1. Direct TIFF header (e.g. "II\x2A\x00" or "MM\x00\x2A")
	if (data[0] == 'I' && data[1] == 'I') || (data[0] == 'M' && data[1] == 'M') {
		return parseTIFF(data)
	}

	// 2. JPEG image (SOI marker: 0xFF, 0xD8)
	if data[0] == 0xFF && data[1] == 0xD8 {
		return parseJPEG(data)
	}

	// 3. PNG image (\x89PNG\r\n\x1a\n)
	if bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) {
		return parsePNG(data)
	}

	return nil, nil
}

func parseJPEG(data []byte) (*Metadata, error) {
	idx := 2
	for idx < len(data)-1 {
		if data[idx] != 0xFF {
			idx++
			continue
		}
		// Skip padding 0xFF bytes
		for idx < len(data) && data[idx] == 0xFF {
			idx++
		}
		if idx >= len(data) {
			break
		}
		marker := data[idx]
		idx++

		// SOS or EOI means image scan starts or ends
		if marker == 0xDA || marker == 0xD9 {
			break
		}
		// Markers without length: RST0-RST7, SOI
		if (marker >= 0xD0 && marker <= 0xD7) || marker == 0x01 {
			continue
		}
		if idx+2 > len(data) {
			break
		}
		segLen := int(binary.BigEndian.Uint16(data[idx : idx+2]))
		if segLen < 2 || idx+segLen > len(data) {
			break
		}
		segData := data[idx+2 : idx+segLen]
		idx += segLen

		// APP1 Marker (0xE1)
		if marker == 0xE1 {
			if bytes.HasPrefix(segData, []byte("Exif\x00\x00")) {
				return parseTIFF(segData[6:])
			}
		}
	}
	return nil, nil
}

func parsePNG(data []byte) (*Metadata, error) {
	idx := 8 // Skip PNG signature
	meta := &Metadata{}
	foundAny := false

	for idx+8 <= len(data) {
		chunkLen := int(binary.BigEndian.Uint32(data[idx : idx+4]))
		if chunkLen < 0 || idx+8+chunkLen+4 > len(data) {
			break
		}
		chunkType := string(data[idx+4 : idx+8])
		chunkData := data[idx+8 : idx+8+chunkLen]
		idx += 8 + chunkLen + 4 // Length + Type + Data + CRC

		if chunkType == "eXIf" {
			if m, err := parseTIFF(chunkData); err == nil && m != nil {
				return m, nil
			}
		} else if chunkType == "tEXt" {
			// Keyword\0Text
			parts := bytes.SplitN(chunkData, []byte{0}, 2)
			if len(parts) == 2 {
				k := strings.ToLower(string(parts[0]))
				v := strings.TrimSpace(string(parts[1]))
				if v != "" {
					switch k {
					case "software":
						meta.Software = v
						foundAny = true
					case "author", "artist":
						meta.Artist = v
						foundAny = true
					case "creation time", "date":
						meta.DateTime = v
						foundAny = true
					}
				}
			}
		} else if chunkType == "IEND" {
			break
		}
	}

	if foundAny {
		return meta, nil
	}
	return nil, nil
}

func parseTIFF(tiff []byte) (*Metadata, error) {
	if len(tiff) < 8 {
		return nil, nil
	}

	var bo binary.ByteOrder
	if tiff[0] == 'I' && tiff[1] == 'I' {
		bo = binary.LittleEndian
	} else if tiff[0] == 'M' && tiff[1] == 'M' {
		bo = binary.BigEndian
	} else {
		return nil, nil
	}

	if bo.Uint16(tiff[2:4]) != 42 {
		return nil, nil
	}

	ifd0Offset := int(bo.Uint32(tiff[4:8]))
	meta := &Metadata{}
	visited := make(map[int]bool)

	parseIFD(tiff, ifd0Offset, bo, meta, 0, visited)

	if meta.Make == "" && meta.Model == "" && meta.Software == "" &&
		meta.DateTime == "" && meta.Artist == "" && meta.LensModel == "" && !meta.HasGPS {
		return nil, nil
	}

	return meta, nil
}

func parseIFD(tiff []byte, offset int, bo binary.ByteOrder, meta *Metadata, depth int, visited map[int]bool) {
	if depth > 4 || offset < 0 || offset+2 > len(tiff) || visited[offset] {
		return
	}
	visited[offset] = true

	numEntries := int(bo.Uint16(tiff[offset : offset+2]))
	offset += 2

	if offset+numEntries*12 > len(tiff) {
		numEntries = (len(tiff) - offset) / 12
	}
	if numEntries > 120 {
		numEntries = 120
	}

	for i := 0; i < numEntries; i++ {
		entryOffset := offset + i*12
		if entryOffset+12 > len(tiff) {
			break
		}

		tagID := bo.Uint16(tiff[entryOffset : entryOffset+2])
		typeID := bo.Uint16(tiff[entryOffset+2 : entryOffset+4])
		count := int(bo.Uint32(tiff[entryOffset+4 : entryOffset+8]))
		valSlice := tiff[entryOffset+8 : entryOffset+12]

		if count <= 0 || count > 100000 {
			continue
		}

		typeSize := getTypeSize(typeID)
		totalBytes := count * typeSize

		var rawVal []byte
		if totalBytes <= 4 {
			rawVal = valSlice[:totalBytes]
		} else {
			dataOffset := int(bo.Uint32(valSlice))
			if dataOffset >= 0 && dataOffset+totalBytes <= len(tiff) {
				rawVal = tiff[dataOffset : dataOffset+totalBytes]
			}
		}

		switch tagID {
		case 0x010F: // Make
			meta.Make = parseASCII(rawVal)
		case 0x0110: // Model
			meta.Model = parseASCII(rawVal)
		case 0x0131: // Software
			meta.Software = parseASCII(rawVal)
		case 0x0132: // DateTime
			meta.DateTime = parseASCII(rawVal)
		case 0x013B: // Artist
			meta.Artist = parseASCII(rawVal)
		case 0xA434: // LensModel
			meta.LensModel = parseASCII(rawVal)
		case 0x8769: // ExifIFD pointer
			if totalBytes == 4 && len(rawVal) == 4 {
				subOffset := int(bo.Uint32(rawVal))
				parseIFD(tiff, subOffset, bo, meta, depth+1, visited)
			}
		case 0x8825: // GPSInfo pointer
			if totalBytes == 4 && len(rawVal) == 4 {
				gpsOffset := int(bo.Uint32(rawVal))
				parseGPSIFD(tiff, gpsOffset, bo, meta, visited)
			}
		}
	}
}

func parseGPSIFD(tiff []byte, offset int, bo binary.ByteOrder, meta *Metadata, visited map[int]bool) {
	if offset < 0 || offset+2 > len(tiff) || visited[offset] {
		return
	}
	visited[offset] = true

	numEntries := int(bo.Uint16(tiff[offset : offset+2]))
	offset += 2

	if offset+numEntries*12 > len(tiff) {
		numEntries = (len(tiff) - offset) / 12
	}
	if numEntries > 50 {
		numEntries = 50
	}

	var latRef, lonRef string
	var latVal, lonVal float64
	hasLat, hasLon := false, false

	for i := 0; i < numEntries; i++ {
		entryOffset := offset + i*12
		if entryOffset+12 > len(tiff) {
			break
		}

		tagID := bo.Uint16(tiff[entryOffset : entryOffset+2])
		typeID := bo.Uint16(tiff[entryOffset+2 : entryOffset+4])
		count := int(bo.Uint32(tiff[entryOffset+4 : entryOffset+8]))
		valSlice := tiff[entryOffset+8 : entryOffset+12]

		if count <= 0 || count > 10000 {
			continue
		}

		typeSize := getTypeSize(typeID)
		totalBytes := count * typeSize

		var rawVal []byte
		if totalBytes <= 4 {
			rawVal = valSlice[:totalBytes]
		} else {
			dataOffset := int(bo.Uint32(valSlice))
			if dataOffset >= 0 && dataOffset+totalBytes <= len(tiff) {
				rawVal = tiff[dataOffset : dataOffset+totalBytes]
			}
		}

		switch tagID {
		case 0x0001: // GPSLatitudeRef
			latRef = parseASCII(rawVal)
		case 0x0002: // GPSLatitude (3 rationals)
			if typeID == 5 && count == 3 && len(rawVal) >= 24 {
				latVal = parseDegrees(rawVal, bo)
				hasLat = true
			}
		case 0x0003: // GPSLongitudeRef
			lonRef = parseASCII(rawVal)
		case 0x0004: // GPSLongitude (3 rationals)
			if typeID == 5 && count == 3 && len(rawVal) >= 24 {
				lonVal = parseDegrees(rawVal, bo)
				hasLon = true
			}
		case 0x0005: // GPSAltitudeRef (1 byte: 0=above, 1=below)
			// handled if needed
		case 0x0006: // GPSAltitude (1 rational)
			if typeID == 5 && count == 1 && len(rawVal) >= 8 {
				num := float64(bo.Uint32(rawVal[0:4]))
				den := float64(bo.Uint32(rawVal[4:8]))
				if den != 0 {
					alt := num / den
					meta.Altitude = &alt
				}
			}
		}
	}

	if hasLat && hasLon {
		if strings.EqualFold(latRef, "S") {
			latVal = -latVal
		}
		if strings.EqualFold(lonRef, "W") {
			lonVal = -lonVal
		}
		meta.HasGPS = true
		meta.Latitude = latVal
		meta.Longitude = lonVal
	}
}

func parseDegrees(raw []byte, bo binary.ByteOrder) float64 {
	degNum := float64(bo.Uint32(raw[0:4]))
	degDen := float64(bo.Uint32(raw[4:8]))
	minNum := float64(bo.Uint32(raw[8:12]))
	minDen := float64(bo.Uint32(raw[12:16]))
	secNum := float64(bo.Uint32(raw[16:20]))
	secDen := float64(bo.Uint32(raw[20:24]))

	var deg, min, sec float64
	if degDen != 0 {
		deg = degNum / degDen
	}
	if minDen != 0 {
		min = minNum / minDen
	}
	if secDen != 0 {
		sec = secNum / secDen
	}

	res := deg + (min / 60.0) + (sec / 3600.0)
	if math.IsNaN(res) || math.IsInf(res, 0) {
		return 0
	}
	return res
}

func parseASCII(raw []byte) string {
	s := strings.TrimRight(string(raw), "\x00 \t\r\n")
	return strings.ToValidUTF8(s, "")
}

func getTypeSize(typeID uint16) int {
	switch typeID {
	case 1, 2, 6, 7: // BYTE, ASCII, SBYTE, UNDEFINED
		return 1
	case 3, 8: // SHORT, SSHORT
		return 2
	case 4, 9, 11: // LONG, SLONG, FLOAT
		return 4
	case 5, 10, 12: // RATIONAL, SRATIONAL, DOUBLE
		return 8
	default:
		return 1
	}
}

func isImage(headers map[string]string, pageURL string, body []byte) bool {
	ct := strings.ToLower(headers["Content-Type"])
	if strings.HasPrefix(ct, "image/") {
		return true
	}
	lowerURL := strings.ToLower(pageURL)
	if strings.HasSuffix(lowerURL, ".jpg") || strings.HasSuffix(lowerURL, ".jpeg") ||
		strings.HasSuffix(lowerURL, ".png") || strings.HasSuffix(lowerURL, ".tif") ||
		strings.HasSuffix(lowerURL, ".tiff") {
		return true
	}
	if len(body) >= 4 {
		if body[0] == 0xFF && body[1] == 0xD8 {
			return true
		}
		if bytes.HasPrefix(body, []byte("\x89PNG\r\n\x1a\n")) {
			return true
		}
	}
	return false
}

func isHTML(headers map[string]string) bool {
	ct := headers["Content-Type"]
	return ct == "" || regexp.MustCompile(`(?i)text/html`).MatchString(ct)
}

func resolveSameOrigin(baseURL *url.URL, ref, targetOnion string) (string, bool) {
	rel, err := url.Parse(ref)
	if err != nil {
		return "", false
	}
	resolved := baseURL.ResolveReference(rel)
	if resolved.Host != "" && !strings.EqualFold(resolved.Host, targetOnion) && !strings.EqualFold(resolved.Host, baseURL.Host) {
		return "", false
	}
	resolved.Fragment = ""
	return resolved.String(), true
}

func dedupeEvidence(in []model.Evidence) []model.Evidence {
	seen := make(map[string]bool)
	var out []model.Evidence
	for _, ev := range in {
		key := fmt.Sprintf("%s|%s|%s", ev.Type, ev.Description, ev.Source)
		if !seen[key] {
			seen[key] = true
			out = append(out, ev)
		}
	}
	return out
}

func defaultFetch(ctx context.Context, targetURL string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "OnionSec/0.1 (+authorized-scan)")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxImageBytes))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}
