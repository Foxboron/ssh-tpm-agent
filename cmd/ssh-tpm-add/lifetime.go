package main

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// parseLifetime accepts the time format used by OpenSSH's ssh-add -t.
func parseLifetime(value string) (uint32, error) {
	const maxSeconds = uint64(^uint32(0))
	if value == "" {
		return 0, fmt.Errorf("invalid lifetime format")
	}

	var total float64
	var seenSeconds bool
	for len(value) > 0 {
		i := 0
		for i < len(value) && ((value[i] >= '0' && value[i] <= '9') || value[i] == '.') {
			i++
		}
		if i == 0 {
			return 0, fmt.Errorf("invalid lifetime format")
		}

		part := value[:i]
		count, err := strconv.ParseFloat(part, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid lifetime: %w", err)
		}

		unit := float64(1)
		seconds := true
		if i < len(value) {
			switch value[i] {
			case 's', 'S':
			case 'm', 'M':
				unit = 60
				seconds = false
			case 'h', 'H':
				unit = 60 * 60
				seconds = false
			case 'd', 'D':
				unit = 24 * 60 * 60
				seconds = false
			case 'w', 'W':
				unit = 7 * 24 * 60 * 60
				seconds = false
			default:
				return 0, fmt.Errorf("invalid lifetime unit %q", value[i])
			}
			i++
		}

		if math.IsNaN(count) || math.IsInf(count, 0) ||
			(part[len(part)-1] == '.' && strings.Contains(part, ".")) {
			return 0, fmt.Errorf("invalid lifetime format")
		}
		if strings.Contains(part, ".") && !seconds {
			return 0, fmt.Errorf("fractional lifetime units must be seconds")
		}
		if seconds {
			if seenSeconds {
				return 0, fmt.Errorf("seconds specified more than once")
			}
			seenSeconds = true
		}

		total += count * unit
		if total > float64(maxSeconds) {
			return 0, fmt.Errorf("lifetime is too large")
		}
		value = value[i:]
	}
	return uint32(total), nil
}
