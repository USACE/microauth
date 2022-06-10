package microauth

import (
	"fmt"
	"testing"
)

var testurl string = "dev2.crrel.mil/auth/realms/dls"
var wantAccountService string = "https://dev2.crrel.mil/auth/realms/dls/account"

func TestFetchRealmInfo(t *testing.T) {
	result, err := FetchRealmInfo(testurl)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(result)
	if result.AccountService != wantAccountService {
		t.Fail()
	}
}
