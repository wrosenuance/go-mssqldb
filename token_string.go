// Code generated by "stringer -type token"; DO NOT EDIT.

package mssql

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[tokenReturnStatus-121]
	_ = x[tokenColMetadata-129]
	_ = x[tokenOrder-169]
	_ = x[tokenError-170]
	_ = x[tokenInfo-171]
	_ = x[tokenReturnValue-172]
	_ = x[tokenLoginAck-173]
	_ = x[tokenFeatureExtAck-174]
	_ = x[tokenRow-209]
	_ = x[tokenNbcRow-210]
	_ = x[tokenEnvChange-227]
	_ = x[tokenSSPI-237]
	_ = x[tokenFedAuthInfo-238]
	_ = x[tokenDone-253]
	_ = x[tokenDoneProc-254]
	_ = x[tokenDoneInProc-255]
}

const (
	_token_name_0 = "tokenReturnStatus"
	_token_name_1 = "tokenColMetadata"
	_token_name_2 = "tokenOrdertokenErrortokenInfotokenReturnValuetokenLoginAcktokenFeatureExtAck"
	_token_name_3 = "tokenRowtokenNbcRow"
	_token_name_4 = "tokenEnvChange"
	_token_name_5 = "tokenSSPItokenFedAuthInfo"
	_token_name_6 = "tokenDonetokenDoneProctokenDoneInProc"
)

var (
	_token_index_2 = [...]uint8{0, 10, 20, 29, 45, 58, 76}
	_token_index_3 = [...]uint8{0, 8, 19}
	_token_index_5 = [...]uint8{0, 9, 25}
	_token_index_6 = [...]uint8{0, 9, 22, 37}
)

func (i token) String() string {
	switch {
	case i == 121:
		return _token_name_0
	case i == 129:
		return _token_name_1
	case 169 <= i && i <= 174:
		i -= 169
		return _token_name_2[_token_index_2[i]:_token_index_2[i+1]]
	case 209 <= i && i <= 210:
		i -= 209
		return _token_name_3[_token_index_3[i]:_token_index_3[i+1]]
	case i == 227:
		return _token_name_4
	case 237 <= i && i <= 238:
		i -= 237
		return _token_name_5[_token_index_5[i]:_token_index_5[i+1]]
	case 253 <= i && i <= 255:
		i -= 253
		return _token_name_6[_token_index_6[i]:_token_index_6[i+1]]
	default:
		return "token(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
