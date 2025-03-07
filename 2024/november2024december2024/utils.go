package november2024december2024

func AppendIfNotPresent(slice []FeatureValue, str FeatureValue) []FeatureValue {

	if str.Key == "" || str.Key == "[]" {
		return slice
	}

	for _, s := range slice {
		if s == str {
			return slice // String already present, return original slice
		}
	}
	return append(slice, str) // String not present, append it to the slice
}

func AppendIfNotPresentStr(slice []string, str string) []string {

	if str == "" || str == "[]" {
		return slice
	}

	for _, s := range slice {
		if s == str {
			return slice // String already present, return original slice
		}
	}
	return append(slice, str) // String not present, append it to the slice
}
