package oidc

import (
	"encoding/base64"
	"testing"
)

var aeskey = []byte("Sj9XWyhTvCChaO8qiDuGoxZokYoSRlB6")

func TestAdd(t *testing.T) {
	encrypted, err := aesEncrypt([]byte("https://google.com"), aeskey)
	t.Log(base64.StdEncoding.EncodeToString(encrypted))
	t.Error(err)
}
