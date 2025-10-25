package proto

import (
    "encoding/binary"
    "math"
)

// Int512 is 512-bit signed integer.
type Int512 struct {
    Low  UInt256 // first 256 bits
    High UInt256 // last 256 bits
}

// Int512FromInt creates new Int512 from int.
func Int512FromInt(v int) Int512 {
    var hi UInt256
    lo := UInt256{Low: UInt128{Low: uint64(v)}}
    if v < 0 {
        hi = UInt256{
            Low:  UInt128{Low: math.MaxUint64, High: math.MaxUint64},
            High: UInt128{Low: math.MaxUint64, High: math.MaxUint64},
        }
        // Sign-extend all bits above 63.
        lo.Low.High = math.MaxUint64
        lo.High = UInt128{Low: math.MaxUint64, High: math.MaxUint64}
    }
    return Int512{
        High: hi,
        Low:  lo,
    }
}



// UInt512 is 512-bit unsigned integer.
type UInt512 struct {
    Low  UInt256 // first 256 bits
    High UInt256 // last 256 bits
}

// UInt512FromInt creates new UInt512 from int.
func UInt512FromInt(v int) UInt512 { return UInt512(Int512FromInt(v)) }

// UInt512FromUInt64 creates new UInt512 from uint64.
func UInt512FromUInt64(v uint64) UInt512 { return UInt512{Low: UInt256{Low: UInt128{Low: v}}} }

func binUInt512(b []byte) UInt512 {
    _ = b[:512/8]
    return UInt512{
        Low: UInt256{
            Low: UInt128{
                Low:  binary.LittleEndian.Uint64(b[0:8]),
                High: binary.LittleEndian.Uint64(b[8:16]),
            },
            High: UInt128{
                Low:  binary.LittleEndian.Uint64(b[16:24]),
                High: binary.LittleEndian.Uint64(b[24:32]),
            },
        },
        High: UInt256{
            Low: UInt128{
                Low:  binary.LittleEndian.Uint64(b[32:40]),
                High: binary.LittleEndian.Uint64(b[40:48]),
            },
            High: UInt128{
                Low:  binary.LittleEndian.Uint64(b[48:56]),
                High: binary.LittleEndian.Uint64(b[56:64]),
            },
        },
    }
}

func binPutUInt512(b []byte, v UInt512) {
    binary.LittleEndian.PutUint64(b[56:64], v.High.High.High)
    binary.LittleEndian.PutUint64(b[48:56], v.High.High.Low)
    binary.LittleEndian.PutUint64(b[40:48], v.High.Low.High)
    binary.LittleEndian.PutUint64(b[32:40], v.High.Low.Low)
    binary.LittleEndian.PutUint64(b[24:32], v.Low.High.High)
    binary.LittleEndian.PutUint64(b[16:24], v.Low.High.Low)
    binary.LittleEndian.PutUint64(b[8:16], v.Low.Low.High)
    binary.LittleEndian.PutUint64(b[0:8], v.Low.Low.Low)
}
