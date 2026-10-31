package nlt

// Record holds the fields of the original's 0x160-byte Record that influence the LogFile table. Field comments
// give the original offset.
type Record struct {
	LSN             string // +0x00 "%I64u"
	TargetVCN       string // +0x60 "0x%X" of the low dword of target_vcn
	Event           string // +0x70
	Detail          string // +0x74
	FileName        string // +0x78
	FullPath        string // +0x7c
	RedoInfo        string // +0x98 redo op name
	UndoInfo        string // +0x9c undo op name
	CreateTime      string // +0xa0
	ModifiedTime    string // +0xa4
	MFTModifiedTime string // +0xa8
	AccessTime      string // +0xac

	ParentRef          uint64 // +0xb0
	RedoFileOff        uint64 // +0xb8 file offset of the redo data
	RedoLen            uint64 // +0xc8
	UndoFileOff        uint64 // +0xd0
	UndoLen            uint64 // +0xd8
	ClusterBlockOffset uint64 // +0xe0, MFT_ClusterIndex
	Runs               string // +0xe8 decoded mapping pairs
	MftVCN             string // +0x140 "0x%X" of the MFT record's VCN (record number / 4)
	MftBlock           uint64 // +0x148 cluster block offset of the MFT record ((record & 3) * 2)
	AttrName           string // +0x150 file attribute name ("Directory", ...)
	EventTime          string // +0x154
	Abnormal           uint32 // +0x158
	AbnormalTime       string // +0x15c
}

// reset is the per-record reset at the top of the record loop (0x40fb56): every listed CString becomes empty and
// the listed POD members are zeroed. All Record fields modelled here are among them.
func (r *Record) reset() { *r = Record{} }
