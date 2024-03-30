package icmpengine

func (ie *ICMPEngine) debugLog(logIt bool, str string) {
	if logIt {
		ie.Log.Info(str)
	}
}
