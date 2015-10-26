package adclient

// #cgo CPPFLAGS: -DOPENLDAP
// #cgo LDFLAGS: -lstdc++ -lldap -lsasl2 -lstdc++ -llber -lresolv
import "C"

import "fmt"
import "strings"
import "strconv"

type ADError struct {
	msg  string
	code int
}

func (err ADError) Error() string {
	return fmt.Sprintf("%v: %v", err.code, err.msg)
}

func catch(err *error) {
	if r := recover(); r != nil {
		err_splitted := strings.SplitN(r.(string), ":", 2)
		if len(err_splitted) != 2 {
			*err = ADError{
				r.(string),
				-1,
			}
		} else {
			code, code_err := strconv.Atoi(err_splitted[0])
			if code_err != nil {
				code = -1
			}
			*err = ADError{
				err_splitted[1],
				code,
			}
		}
	}
}

var ad Adclient

func New() {
	ad = NewAdclient()
}

func Delete() {
	DeleteAdclient(ad)
}

func Login(uri interface{}, user string, passwd string, sb string) (err error) {
	defer catch(&err)
	switch uri.(type) {
	case string:
		ad.Login(uri.(string), user, passwd, sb)
	case []string:
		uries := NewStringVector()
		defer DeleteStringVector(uries)
		for _, suri := range uri.([]string) {
			uries.Add(suri)
		}
		ad.Login(uries, user, passwd, sb)
	default:
		err = ADError{
			fmt.Sprintf("unknown uri type - %#v", uri),
			-1,
		}
	}
	return
}

func GetUserGroups(user string) (result []string, err error) {
	defer catch(&err)
	groups := ad.GetUserGroups(user)
	defer DeleteStringVector(groups)
	result = make([]string, groups.Size())
	for i := 0; i < int(groups.Size()); i++ {
		result[i] = groups.Get(i)
	}
	return
}
