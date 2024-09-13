package august2024august2024v2

import (
	"fmt"
)

func CalculateImageStatus(finalScore int) RiskStatus {
	if finalScore < HighStatusValue {
		return RiskStatusHighrisk
	} else if finalScore >= LowStatusValue {
		return RiskStatusLowrisk
	}
	return RiskStatusMediumrisk

}

func convIntPointerToString(value *int) string {
	if value != nil {
		return fmt.Sprint(*value)
	}
	return ""
}
