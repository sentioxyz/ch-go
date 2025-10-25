package proto

func Decimal128FromInt(v int) Decimal128 {
	return Decimal128(Int128FromInt(v))
}

func Decimal256FromInt(v int) Decimal256 {
    return Decimal256(Int256FromInt(v))
}

func Decimal512FromInt(v int) Decimal512 {
    return Decimal512(Int512FromInt(v))
}
