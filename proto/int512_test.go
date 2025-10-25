package proto

import (
    "encoding/binary"
    "math"
    "testing"

    "github.com/stretchr/testify/require"
)

func TestUInt512_FromIntAndUInt64(t *testing.T) {
    t.Run("FromInt_Positive", func(t *testing.T) {
        u := UInt512FromInt(42)
        require.Equal(t, uint64(42), u.Low.Low.Low)
        require.Equal(t, uint64(0), u.Low.Low.High)
        require.Equal(t, uint64(0), u.Low.High.Low)
        require.Equal(t, uint64(0), u.Low.High.High)
        require.Equal(t, uint64(0), u.High.Low.Low)
        require.Equal(t, uint64(0), u.High.Low.High)
        require.Equal(t, uint64(0), u.High.High.Low)
        require.Equal(t, uint64(0), u.High.High.High)
    })
    t.Run("FromInt_Negative_SignExtend", func(t *testing.T) {
        u := UInt512FromInt(-1)
        // Two's-complement sign-extended: all higher words must be all ones.
        require.Equal(t, uint64(math.MaxUint64), u.Low.Low.Low)  // -1 cast to uint64
        require.Equal(t, uint64(math.MaxUint64), u.Low.Low.High) // sign extend into Low.High
        require.Equal(t, uint64(math.MaxUint64), u.Low.High.Low)
        require.Equal(t, uint64(math.MaxUint64), u.Low.High.High)
        require.Equal(t, uint64(math.MaxUint64), u.High.Low.Low)
        require.Equal(t, uint64(math.MaxUint64), u.High.Low.High)
        require.Equal(t, uint64(math.MaxUint64), u.High.High.Low)
        require.Equal(t, uint64(math.MaxUint64), u.High.High.High)
    })
    t.Run("FromUInt64", func(t *testing.T) {
        u := UInt512FromUInt64(0xDEADBEEFCAFEBABE)
        require.Equal(t, uint64(0xDEADBEEFCAFEBABE), u.Low.Low.Low)
        require.Equal(t, uint64(0), u.Low.Low.High)
        require.Equal(t, uint64(0), u.Low.High.Low)
        require.Equal(t, uint64(0), u.Low.High.High)
        require.Equal(t, uint64(0), u.High.Low.Low)
        require.Equal(t, uint64(0), u.High.Low.High)
        require.Equal(t, uint64(0), u.High.High.Low)
        require.Equal(t, uint64(0), u.High.High.High)
    })
}

func TestBinUInt512_RoundTrip_FromInt(t *testing.T) {
    cases := []int{0, 1, -1, 42, -42, 1234567890, -1234567890, math.MaxInt32, math.MinInt32}
    for _, v := range cases {
        t.Run("v="+itoa(v), func(t *testing.T) {
            i := Int512FromInt(v)
            want := UInt512(i)
            buf := make([]byte, 64)
            binPutUInt512(buf, want)
            got := binUInt512(buf)
            require.Equal(t, want, got)
        })
    }
}

func TestBinUInt512_Layout(t *testing.T) {
    // Fill bytes with deterministic pattern: b[i] = i
    var buf [64]byte
    for i := 0; i < len(buf); i++ {
        buf[i] = byte(i)
    }
    u := binUInt512(buf[:])
    // Validate mapping per 64-bit little-endian lanes.
    // Low.Low.Low  uses bytes [0:8]
    require.Equal(t, binary.LittleEndian.Uint64(buf[0:8]), u.Low.Low.Low)
    require.Equal(t, binary.LittleEndian.Uint64(buf[8:16]), u.Low.Low.High)
    require.Equal(t, binary.LittleEndian.Uint64(buf[16:24]), u.Low.High.Low)
    require.Equal(t, binary.LittleEndian.Uint64(buf[24:32]), u.Low.High.High)
    require.Equal(t, binary.LittleEndian.Uint64(buf[32:40]), u.High.Low.Low)
    require.Equal(t, binary.LittleEndian.Uint64(buf[40:48]), u.High.Low.High)
    require.Equal(t, binary.LittleEndian.Uint64(buf[48:56]), u.High.High.Low)
    require.Equal(t, binary.LittleEndian.Uint64(buf[56:64]), u.High.High.High)

    // Write back and compare bytes.
    var out [64]byte
    binPutUInt512(out[:], u)
    require.Equal(t, buf, out)
}

// minimal itoa helper to avoid strconv import churn in tests
func itoa(v int) string {
    // This is only used for test names; keep it simple.
    if v == 0 {
        return "0"
    }
    neg := false
    if v < 0 {
        neg = true
        v = -v
    }
    var b [20]byte
    i := len(b)
    for v > 0 {
        i--
        b[i] = byte('0' + v%10)
        v /= 10
    }
    if neg {
        i--
        b[i] = '-'
    }
    return string(b[i:])
}

