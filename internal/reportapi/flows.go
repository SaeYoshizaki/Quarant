package reportapi

func LoadFlows(path string) ([]FlowRecord, error) {
	return loadFlowRecords(path)
}
