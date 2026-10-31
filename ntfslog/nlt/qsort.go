package nlt

// msvcQsort is the MSVC 2010 CRT qsort (qsort.c: median-of-three quicksort with an explicit stack and a selection
// "shortsort" for partitions of at most 8 elements). It is not stable; porting it keeps the original's order of
// equal keys.
func msvcQsort[T any](a []T, comp func(x, y *T) int) {
	const cutoff = 8
	if len(a) < 2 {
		return
	}
	var lostk, histk [64]int
	stkptr := 0
	lo, hi := 0, len(a)-1
	swap := func(i, j int) {
		if i != j {
			a[i], a[j] = a[j], a[i]
		}
	}
	c := func(i, j int) int { return comp(&a[i], &a[j]) }
	for {
		size := hi - lo + 1
		if size <= cutoff {
			for h := hi; h > lo; h-- { // shortsort
				max := lo
				for p := lo + 1; p <= h; p++ {
					if c(p, max) > 0 {
						max = p
					}
				}
				swap(max, h)
			}
		} else {
			mid := lo + size/2
			if c(lo, mid) > 0 {
				swap(lo, mid)
			}
			if c(lo, hi) > 0 {
				swap(lo, hi)
			}
			if c(mid, hi) > 0 {
				swap(mid, hi)
			}
			loguy, higuy := lo, hi
			for {
				if mid > loguy {
					for {
						loguy++
						if !(loguy < mid && c(loguy, mid) <= 0) {
							break
						}
					}
				}
				if mid <= loguy {
					for {
						loguy++
						if !(loguy <= hi && c(loguy, mid) <= 0) {
							break
						}
					}
				}
				for {
					higuy--
					if !(higuy > mid && c(higuy, mid) > 0) {
						break
					}
				}
				if higuy < loguy {
					break
				}
				swap(loguy, higuy)
				if mid == higuy {
					mid = loguy
				}
			}
			higuy++
			if mid < higuy {
				for {
					higuy--
					if !(higuy > mid && c(higuy, mid) == 0) {
						break
					}
				}
			}
			if mid >= higuy {
				for {
					higuy--
					if !(higuy > lo && c(higuy, mid) == 0) {
						break
					}
				}
			}
			if higuy-lo >= hi-loguy {
				if lo < higuy {
					lostk[stkptr], histk[stkptr] = lo, higuy
					stkptr++
				}
				if loguy < hi {
					lo = loguy
					continue
				}
			} else {
				if loguy < hi {
					lostk[stkptr], histk[stkptr] = loguy, hi
					stkptr++
				}
				if lo < higuy {
					hi = higuy
					continue
				}
			}
		}
		stkptr--
		if stkptr < 0 {
			return
		}
		lo, hi = lostk[stkptr], histk[stkptr]
	}
}

func cmpU64(a, b uint64) int {
	switch {
	case a > b:
		return 1
	case a < b:
		return -1
	}
	return 0
}
