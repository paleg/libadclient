package adclient

// #cgo CPPFLAGS: -DOPENLDAP -DKRB5
// #cgo LDFLAGS: -lstdc++ -lldap -lsasl2 -lstdc++ -llber -lresolv -lkrb5
import "C"

import "fmt"
import "strings"
import "strconv"

type ADError struct {
	msg  string
	code int
}

type ADConnParams struct {
	Domain      string
	Site        string
	Uries       []string
	Binddn      string
	Bindpw      string
	Search_base string
	Secured     bool
	UseGSSAPI   bool
	Nettimeout  int
	Timelimit   int
}

func DefaultADConnParams() (params ADConnParams) {
	params.Nettimeout = -1
	params.Timelimit = -1
	params.Secured = true
	params.UseGSSAPI = false
	return
}

func LdapPrefix() string {
	return GetAdclientLdap_prefix()
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

func vector2slice(vector StringVector) []string {
	result := make([]string, vector.Size())
	for i := 0; i < int(vector.Size()); i++ {
		result[i] = vector.Get(i)
	}
	return result
}

func commonStringToSlice(f func(string) StringVector, thing string) (result []string, err error) {
	defer catch(&err)
	vector := f(thing)
	defer DeleteStringVector(vector)
	result = vector2slice(vector)
	return
}

func common2StringsToSlice(f func(string, string) StringVector, thing1 string, thing2 string) (result []string, err error) {
	defer catch(&err)
	vector := f(thing1, thing2)
	defer DeleteStringVector(vector)
	result = vector2slice(vector)
	return
}

func commonStringsIntToSlice(f func(string, int) StringVector, thing1 string, thing2 int) (result []string, err error) {
	defer catch(&err)
	vector := f(thing1, thing2)
	defer DeleteStringVector(vector)
	result = vector2slice(vector)
	return
}

func commonEmptyToSlice(f func() StringVector) (result []string, err error) {
	defer catch(&err)
	vector := f()
	defer DeleteStringVector(vector)
	result = vector2slice(vector)
	return
}

var ad Adclient

func New() {
	ad = NewAdclient()
}

func Delete() {
	DeleteAdclient(ad)
}

func Login(_params ADConnParams) (err error) {
	defer catch(&err)

	params := NewAdConnParams()
	defer DeleteAdConnParams(params)

	params.SetDomain(_params.Domain)
	params.SetSite(_params.Site)
	params.SetBinddn(_params.Binddn)
	params.SetBindpw(_params.Bindpw)
	params.SetSearch_base(_params.Search_base)
	params.SetSecured(_params.Secured)
	params.SetUse_gssapi(_params.UseGSSAPI)
	params.SetNettimeout(_params.Nettimeout)
	params.SetTimelimit(_params.Timelimit)

	uries := NewStringVector()
	defer DeleteStringVector(uries)
	for _, uri := range _params.Uries {
		uries.Add(uri)
	}
	params.SetUries(uries)

	ad.Login(params)
	return
}

func LoginOld(uri interface{}, user string, passwd string, sb string, secured bool) (err error) {
	defer catch(&err)

	args := DefaultADConnParams()
	args.Binddn = user
	args.Bindpw = passwd
	args.Search_base = sb
	args.UseGSSAPI = secured

	switch uri.(type) {
	case string:
		args.Domain = uri.(string)
	case []string:
		args.Uries = uri.([]string)
	default:
		err = ADError{
			fmt.Sprintf("unknown uri type - %#v", uri),
			-1,
		}
	}
	Login(args)
	return
}

func BindedUri() (result string) {
	return ad.Binded_uri()
}

func SearchBase() (result string) {
	return ad.Search_base()
}

func LoginMethod() (result string) {
	return ad.Login_method()
}

func GroupAddUser(group string, user string) (err error) {
	defer catch(&err)
	ad.GroupAddUser(group, user)
	return
}

func GroupRemoveUser(group string, user string) (err error) {
	defer catch(&err)
	ad.GroupRemoveUser(group, user)
	return
}

func CreateComputer(name string, container string) (err error) {
	defer catch(&err)
	ad.CreateComputer(name, container)
	return
}

func CreateUser(cn string, container string, user_short string) (err error) {
	defer catch(&err)
	ad.CreateUser(cn, container, user_short)
	return
}

func CreateGroup(cn string, container string, group_short string) (err error) {
	defer catch(&err)
	ad.CreateGroup(cn, container, group_short)
	return
}

func DeleteDN(dn string) (err error) {
	defer catch(&err)
	ad.DeleteDN(dn)
	return
}

func CreateOU(ou string) (err error) {
	defer catch(&err)
	ad.CreateOU(ou)
	return
}

func EnableUser(user string) (err error) {
	defer catch(&err)
	ad.EnableUser(user)
	return
}

func DisableUser(user string) (err error) {
	defer catch(&err)
	ad.DisableUser(user)
	return
}

func UnLockUser(user string) (err error) {
	defer catch(&err)
	ad.UnLockUser(user)
	return
}

func SetUserPassword(user string, password string) (err error) {
	defer catch(&err)
	ad.SetUserPassword(user, password)
	return
}

func SetUserDialinAllowed(user string) (err error) {
	defer catch(&err)
	ad.SetUserDialinAllowed(user)
	return
}

func SetUserDialinDisabled(user string) (err error) {
	defer catch(&err)
	ad.SetUserDialinDisabled(user)
	return
}

func CheckUserPassword(user string, password string) (result bool, err error) {
	defer catch(&err)
	result = ad.CheckUserPassword(user, password)
	return
}

func SetUserSN(user string, sn string) (err error) {
	defer catch(&err)
	ad.SetUserSN(user, sn)
	return
}

func SetUserInitials(user string, initials string) (err error) {
	defer catch(&err)
	ad.SetUserInitials(user, initials)
	return
}

func SetUserGivenName(user string, givenName string) (err error) {
	defer catch(&err)
	ad.SetUserGivenName(user, givenName)
	return
}

func SetUserDisplayName(user string, displayName string) (err error) {
	defer catch(&err)
	ad.SetUserDisplayName(user, displayName)
	return
}

func SetUserRoomNumber(user string, roomNum string) (err error) {
	defer catch(&err)
	ad.SetUserRoomNumber(user, roomNum)
	return
}

func SetUserAddress(user string, streetAddress string) (err error) {
	defer catch(&err)
	ad.SetUserAddress(user, streetAddress)
	return
}

func SetUserInfo(user string, info string) (err error) {
	defer catch(&err)
	ad.SetUserInfo(user, info)
	return
}

func SetUserTitle(user string, title string) (err error) {
	defer catch(&err)
	ad.SetUserTitle(user, title)
	return
}

func SetUserDepartment(user string, department string) (err error) {
	defer catch(&err)
	ad.SetUserDepartment(user, department)
	return
}

func SetUserCompany(user string, company string) (err error) {
	defer catch(&err)
	ad.SetUserCompany(user, company)
	return
}

func SetUserPhone(user string, phone string) (err error) {
	defer catch(&err)
	ad.SetUserPhone(user, phone)
	return
}

func SetUserDescription(user string, descr string) (err error) {
	defer catch(&err)
	ad.SetUserDescription(user, descr)
	return
}

func GetUserControls(user string) (result map[string]bool, err error) {
	result = make(map[string]bool)
	defer catch(&err)
	cmap := ad.GetUserControls(user)
	defer DeleteStringBoolMap(cmap)
	keys := cmap.Keys()
	for i := 0; i < int(keys.Size()); i++ {
		key := keys.Get(i)
		result[key] = cmap.Get(key)
	}
	return
}

func GetUserControl(user string, control string) (result bool, err error) {
	defer catch(&err)
	result = ad.GetUserControl(user, control)
	return
}

func IfUserExpired(user string) (result bool, err error) {
	defer catch(&err)
	result = ad.IfUserExpired(user)
	return
}

func IfUserLocked(user string) (result bool, err error) {
	defer catch(&err)
	result = ad.IfUserLocked(user)
	return
}

func IfUserDisabled(user string) (result bool, err error) {
	defer catch(&err)
	result = ad.IfUserDisabled(user)
	return
}

func IfUserMustChangePassword(user string) (result bool, err error) {
	defer catch(&err)
	result = ad.IfUserMustChangePassword(user)
	return
}

func IfUserDontExpirePassword(user string) (result bool, err error) {
	defer catch(&err)
	result = ad.IfUserDontExpirePassword(user)
	return
}

func GetObjectDN(object string) (result string, err error) {
	defer catch(&err)
	result = ad.GetObjectDN(object)
	return
}

func GetUserDisplayName(user string) (result string, err error) {
	defer catch(&err)
	result = ad.GetUserDisplayName(user)
	return
}

func IfDialinUser(user string) (result bool, err error) {
	defer catch(&err)
	result = ad.IfDialinUser(user)
	return
}

func IfDNExists(args ...string) (result bool, err error) {
	defer catch(&err)
	switch len(args) {
	case 1:
		result = ad.IfDNExists(args[0])
	case 2:
		result = ad.IfDNExists(args[0], args[1])
	default:
		panic("wrong number of args for IfDNExists")
	}
	return
}

func GetGroups() ([]string, error) {
	return commonEmptyToSlice(ad.GetGroups)
}

func GetUsers() ([]string, error) {
	return commonEmptyToSlice(ad.GetUsers)
}

func GetOUs() ([]string, error) {
	return commonEmptyToSlice(ad.GetOUs)
}

func GetDialinUsers() ([]string, error) {
	return commonEmptyToSlice(ad.GetDialinUsers)
}

func GetDisabledUsers() ([]string, error) {
	return commonEmptyToSlice(ad.GetDisabledUsers)
}

func GetUserGroups(user string, nested bool) (result []string, err error) {
	defer catch(&err)
	vector := ad.GetUserGroups(user, nested)
	defer DeleteStringVector(vector)
	result = vector2slice(vector)
	return
}

func GetUsersInGroup(group string, nested bool) (result []string, err error) {
	defer catch(&err)
	vector := ad.GetUsersInGroup(group, nested)
	defer DeleteStringVector(vector)
	result = vector2slice(vector)
	return
}

func GetGroupsInOU(OU string, scope int) (result []string, err error) {
	return commonStringsIntToSlice(ad.GetGroupsInOU, OU, scope)
}

func GetComputersInOU(OU string, scope int) (result []string, err error) {
	return commonStringsIntToSlice(ad.GetComputersInOU, OU, scope)
}

func GetOUsInOU(OU string, scope int) (result []string, err error) {
	return commonStringsIntToSlice(ad.GetOUsInOU, OU, scope)
}

func GetUsersInOU(OU string, scope int) (result []string, err error) {
	return commonStringsIntToSlice(ad.GetUsersInOU, OU, scope)
}

/*
   struct berval getBinaryObjectAttribute(string object, string attribute);
*/

func GetObjectAttribute(object string, attribute string) (result []string, err error) {
	return common2StringsToSlice(ad.GetObjectAttribute, object, attribute)
}

func SearchDN(search_base string, filter string, scope int) (result []string, err error) {
	defer catch(&err)
	vector := ad.SearchDN(search_base, filter, scope)
	defer DeleteStringVector(vector)
	result = vector2slice(vector)
	return
}

/*
   map < string, map < string, std::vector<string> > > search(string OU, int scope, string filter, const std::vector <string> &attributes);
*/

func GetObjectAttributes(object string, attrs ...string) (result map[string][]string, err error) {
	cattrs := NewStringVector()
	defer DeleteStringVector(cattrs)
	if len(attrs) == 0 {
		cattrs.Add("*")
	} else {
		for _, attr := range attrs {
			cattrs.Add(attr)
		}
	}

	result = make(map[string][]string)
	defer catch(&err)
	cmap := ad.GetObjectAttributes(object, cattrs)
	defer DeleteString_VectorString_Map(cmap)
	keys := cmap.Keys()
	for i := 0; i < int(keys.Size()); i++ {
		key := keys.Get(i)
		value := cmap.Get(key)
		result[key] = vector2slice(value)
	}
	return
}

/*
   map <string, std::vector <string> > GetObjectAttributes(string object, const std::vector<string> &attributes);
*/
