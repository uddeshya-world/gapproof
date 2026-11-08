package models

import (
	"errors"
	"fmt"
	"io"
)

// A minimal protobuf wire-format reader, enough to find ONNX tensors that
// point at external data. It works on byte ranges of an io.ReaderAt, so
// large raw_data fields are skipped, never loaded.

type pbField struct {
	num      int
	wire     int
	varint   uint64
	off, len int64 // payload range for length-delimited fields
}

const pbMaxDepth = 32

func pbVarint(r io.ReaderAt, at, end int64) (uint64, int64, error) {
	var buf [10]byte
	n := min(int64(len(buf)), end-at)
	if n <= 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	k, err := r.ReadAt(buf[:n], at)
	if int64(k) < n && err != nil {
		return 0, 0, err
	}
	var v uint64
	for i := range k {
		b := buf[i]
		v |= uint64(b&0x7f) << (7 * i)
		if b < 0x80 {
			return v, int64(i + 1), nil
		}
	}
	return 0, 0, errors.New("protobuf: bad varint")
}

// pbEach calls fn for every field in [start, end).
func pbEach(r io.ReaderAt, start, end int64, fn func(pbField) error) error {
	for at := start; at < end; {
		key, n, err := pbVarint(r, at, end)
		if err != nil {
			return err
		}
		at += n
		f := pbField{num: int(key >> 3), wire: int(key & 7)}
		switch f.wire {
		case 0:
			if f.varint, n, err = pbVarint(r, at, end); err != nil {
				return err
			}
			at += n
		case 1:
			at += 8
		case 5:
			at += 4
		case 2:
			l, n, err := pbVarint(r, at, end)
			if err != nil {
				return err
			}
			at += n
			if l > uint64(end-at) {
				return errors.New("protobuf: field length runs past its message")
			}
			f.off, f.len = at, int64(l)
			at += int64(l)
		default:
			return fmt.Errorf("protobuf: unsupported wire type %d", f.wire)
		}
		if at > end {
			return errors.New("protobuf: truncated field")
		}
		if err := fn(f); err != nil {
			return err
		}
	}
	return nil
}

func pbString(r io.ReaderAt, f pbField, max int64) (string, error) {
	if f.wire != 2 || f.len > max {
		return "", errors.New("protobuf: bad string field")
	}
	b := make([]byte, f.len)
	_, err := r.ReadAt(b, f.off)
	return string(b), err
}

// onnxExternal is one tensor that stores its data outside the .onnx file.
type onnxExternal struct {
	tensor   string
	location string
}

// ONNX field numbers (onnx.proto3).
const (
	onnxModelGraph       = 7
	onnxGraphNode        = 1
	onnxGraphInitializer = 5
	onnxNodeAttribute    = 5
	onnxAttrT            = 5
	onnxAttrG            = 6
	onnxAttrTensors      = 10
	onnxAttrGraphs       = 11
	onnxTensorName       = 8
	onnxTensorExternal   = 13
	onnxTensorLocation   = 14
	onnxEntryKey         = 1
	onnxEntryValue       = 2
	onnxDataExternal     = 1
)

// parseONNX walks the model graph (and subgraphs in node attributes) and
// returns every tensor stored as external data.
func parseONNX(r io.ReaderAt, size int64) ([]onnxExternal, error) {
	var out []onnxExternal
	var graph func(start, end int64, depth int) error

	tensor := func(start, end int64) error {
		var name, location string
		external := false
		err := pbEach(r, start, end, func(f pbField) error {
			switch f.num {
			case onnxTensorName:
				s, err := pbString(r, f, 4096)
				name = s
				return err
			case onnxTensorLocation:
				external = external || f.varint == onnxDataExternal
			case onnxTensorExternal:
				external = true
				var k, v string
				err := pbEach(r, f.off, f.off+f.len, func(e pbField) error {
					var err error
					switch e.num {
					case onnxEntryKey:
						k, err = pbString(r, e, 4096)
					case onnxEntryValue:
						v, err = pbString(r, e, 4096)
					}
					return err
				})
				if err != nil {
					return err
				}
				if k == "location" {
					location = v
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		if external {
			if location == "" {
				return fmt.Errorf("onnx: tensor %q is external but has no location", name)
			}
			out = append(out, onnxExternal{tensor: name, location: location})
		}
		return nil
	}

	graph = func(start, end int64, depth int) error {
		if depth > pbMaxDepth {
			return errors.New("onnx: subgraphs nested too deeply")
		}
		return pbEach(r, start, end, func(f pbField) error {
			switch {
			case f.num == onnxGraphInitializer && f.wire == 2:
				return tensor(f.off, f.off+f.len)
			case f.num == onnxGraphNode && f.wire == 2:
				return pbEach(r, f.off, f.off+f.len, func(n pbField) error {
					if n.num != onnxNodeAttribute || n.wire != 2 {
						return nil
					}
					return pbEach(r, n.off, n.off+n.len, func(a pbField) error {
						switch {
						case (a.num == onnxAttrT || a.num == onnxAttrTensors) && a.wire == 2:
							return tensor(a.off, a.off+a.len)
						case (a.num == onnxAttrG || a.num == onnxAttrGraphs) && a.wire == 2:
							return graph(a.off, a.off+a.len, depth+1)
						}
						return nil
					})
				})
			}
			return nil
		})
	}

	sawGraph := false
	err := pbEach(r, 0, size, func(f pbField) error {
		if f.num == onnxModelGraph && f.wire == 2 {
			sawGraph = true
			return graph(f.off, f.off+f.len, 0)
		}
		return nil
	})
	if err == nil && !sawGraph {
		err = errors.New("onnx: no graph in model")
	}
	return out, err
}
