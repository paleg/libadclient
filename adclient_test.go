package adclient

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"testing"
)

type Group struct {
	CommonName string
	Container  string
	ShortName  string
}

type User struct {
	CommonName  string
	Container   string
	ShortName   string
	Password    string
	SN          string
	Initials    string
	GivenName   string
	DisplayName string
	RoomNumber  string
	Address     string
	Info        string
	Title       string
	Department  string
	Company     string
	Phone       string
	Description string
}

var LDAPServer = []string{"domain.local"}
var LDAPUser = "rwuser"
var LDAPPasswd = "rwuserpassword"
var LDAPSearchBase = "DC=domain,DC=local"

var TestOU = "OU=GhostBusters," + LDAPSearchBase
var TestUser1 = User{CommonName: "Egon Spengler", Container: TestOU, ShortName: "Spengler.Egon.Dr", Password: "engoSiunah5m",
	SN: "Spengler", Initials: "Dr", GivenName: "Egon", DisplayName: "Dr. Egon Spengler, Ph.D.", RoomNumber: "Basement",
	Address: "110 N. Moore Street, New York", Info: "Former professor of paranormal studies at the Columbia University",
	Title: "Founder", Department: "Science", Company: "GhostBusters", Phone: "555-2368", Description: "Collects spores, molds, and fungus"}
var TestUser2 = User{CommonName: "Peter Venkman", Container: TestOU, ShortName: "Venkman.Peter.Dr"}
var TestGroup1 = Group{"GBGroup1", TestOU, "GBGroup1"}
var TestGroup2 = Group{"GBGroup2", TestOU, "GBGroup2"}

func TestMain(m *testing.M) {
	ret := 1
	New()
	err := Login(LDAPServer, LDAPUser, LDAPPasswd, LDAPSearchBase, true)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("Binded to '%+v'\n", BindedUri())
		if dirty_env, err := IfDNExists(TestOU); err != nil {
			fmt.Println(err)
		} else if dirty_env {
			fmt.Printf("'%+v' exists, remove it before testing\n", TestOU)
		} else {
			ret = m.Run()
		}
	}
	Delete()
	os.Exit(ret)
}

func TestCreateUsers(t *testing.T) {
	t.Logf("Creating '%+v'", TestUser1.CommonName)
	err1 := CreateUser(TestUser1.CommonName, TestUser1.Container, TestUser1.ShortName)
	if err1 != nil {
		t.Fatalf("Failed to CreateUser('%+v') - '%+v'", TestUser1.CommonName, err1)
	}
	t.Logf("Creating '%+v'", TestUser2.CommonName)
	err2 := CreateUser(TestUser2.CommonName, TestUser2.Container, TestUser2.ShortName)
	if err2 != nil {
		t.Fatalf("Failed to CreateUser('%+v') - '%+v'", TestUser2.CommonName, err2)
	}
}

func TestCreateGroups(t *testing.T) {
	t.Logf("Creating '%+v'", TestGroup1.CommonName)
	err1 := CreateGroup(TestGroup1.CommonName, TestGroup1.Container, TestGroup1.ShortName)
	if err1 != nil {
		t.Fatalf("Failed to CreateGroup('%+v') - '%+v'", TestGroup1.CommonName, err1)
	}
	t.Logf("Creating '%+v'", TestGroup2.CommonName)
	err2 := CreateGroup(TestGroup2.CommonName, TestGroup2.Container, TestGroup2.ShortName)
	if err2 != nil {
		t.Fatalf("Failed to CreateGroup('%+v') - '%+v'", TestGroup2.CommonName, err2)
	}
}

func TestUserProps(t *testing.T) {
	t.Logf("Setting '%+v' props", TestUser1.CommonName)
	// TODO: check err
	SetUserPassword(TestUser1.ShortName, TestUser1.Password)
	EnableUser(TestUser1.ShortName)
	SetUserSN(TestUser1.ShortName, TestUser1.SN)
	SetUserInitials(TestUser1.ShortName, TestUser1.Initials)
	SetUserGivenName(TestUser1.ShortName, TestUser1.GivenName)
	SetUserDisplayName(TestUser1.ShortName, TestUser1.DisplayName)
	SetUserRoomNumber(TestUser1.ShortName, TestUser1.RoomNumber)
	SetUserAddress(TestUser1.ShortName, TestUser1.Address)
	SetUserInfo(TestUser1.ShortName, TestUser1.Info)
	SetUserTitle(TestUser1.ShortName, TestUser1.Title)
	SetUserDepartment(TestUser1.ShortName, TestUser1.Department)
	SetUserCompany(TestUser1.ShortName, TestUser1.Company)
	SetUserPhone(TestUser1.ShortName, TestUser1.Phone)
	SetUserDescription(TestUser1.ShortName, TestUser1.Description)

	t.Logf("Checking '%+v' props", TestUser1.CommonName)
	if ok, err := CheckUserPassword(TestUser1.ShortName, TestUser1.Password); err != nil {
		t.Fatalf("Failed to CheckUserPassword('%+v') - '%+v'", TestUser1.ShortName, err)
	} else if !ok {
		t.Errorf("'%+v' password expected to be '%+v'", TestUser1.CommonName, TestUser1.Password)
	}
	if props, err := GetObjectAttributes(TestUser1.ShortName); err != nil {
		t.Fatalf("Failed to GetObjectAttributes('%+v') - '%+v'", TestUser1.ShortName, err)
	} else {
		if props["pwdLastSet"][0] == "0" {
			t.Errorf("User '%+v' pwdLastSet expected to be set", TestUser1.CommonName)
		}
		checkmap := map[string]string{
			"name":                       TestUser1.CommonName,
			"company":                    TestUser1.Company,
			"title":                      TestUser1.Title,
			"initials":                   TestUser1.Initials,
			"sn":                         TestUser1.SN,
			"cn":                         TestUser1.CommonName,
			"displayName":                TestUser1.DisplayName,
			"info":                       TestUser1.Info,
			"streetAddress":              TestUser1.Address,
			"telephoneNumber":            TestUser1.Phone,
			"distinguishedName":          "CN=" + TestUser1.CommonName + "," + TestOU,
			"department":                 TestUser1.Department,
			"givenName":                  TestUser1.GivenName,
			"sAMAccountName":             TestUser1.ShortName,
			"description":                TestUser1.Description,
			"physicalDeliveryOfficeName": TestUser1.RoomNumber,
		}
		for prop, value := range checkmap {
			if props[prop][0] != value {
				t.Errorf("User '%+v' %+v expected to be '%+v', got '%+v'", TestUser1.CommonName, prop, value, props[prop][0])
			}
		}
	}

	//controls: map[string]bool{"locked":false, "mustChangePassword":false, "disabled":false, "dontExpirePassword":true, "expired":false}
	if controls, err := GetUserControls(TestUser1.ShortName); err != nil {
		t.Fatalf("Failed to GetUserControls('%+v') - '%+v'", TestUser1.CommonName, err)
	} else {
		if controls["disabled"] {
			t.Errorf("User '%+v' expected to be enabled", TestUser1.CommonName)
		}
	}
	if controls, err := GetUserControls(TestUser2.ShortName); err != nil {
		t.Fatalf("Failed to GetUserControls('%+v') - '%+v'", TestUser2.CommonName, err)
	} else {
		if !controls["disabled"] {
			t.Errorf("User '%+v' expected to be disabled", TestUser2.CommonName)
		}
	}
}

func TestUserGroups(t *testing.T) {
	t.Logf("Adding '%+v' to '%+v'", TestUser1.CommonName, TestGroup1.CommonName)
	if err := GroupAddUser(TestGroup1.ShortName, TestUser1.ShortName); err != nil {
		t.Fatalf("Failed to GroupAddUser('%+v', '%+v') - '%+v'", TestGroup1.ShortName, TestUser1.ShortName, err)
	}
	t.Logf("Adding '%+v' to '%+v'", TestUser1.CommonName, TestGroup2.CommonName)
	if err := GroupAddUser(TestGroup2.ShortName, TestUser1.ShortName); err != nil {
		t.Fatalf("Failed to GroupAddUser('%+v', '%+v') - '%+v'", TestGroup2.ShortName, TestUser1.ShortName, err)
	}
	t.Logf("Adding '%+v' to '%+v'", TestUser2.CommonName, TestGroup2.CommonName)
	if err := GroupAddUser(TestGroup2.ShortName, TestUser2.ShortName); err != nil {
		t.Fatalf("Failed to GroupAddUser('%+v', '%+v') - '%+v'", TestGroup2.ShortName, TestUser2.ShortName, err)
	}

	t.Logf("Checking '%+v' memberof", TestUser1.CommonName)
	if groups, err := GetUserGroups(TestUser1.ShortName); err != nil {
		t.Fatalf("Failed to GetUserGroups('%+v') - '%+v'", TestUser1.ShortName, err)
	} else {
		expected := []string{TestGroup1.CommonName, TestGroup2.CommonName}
		sort.Strings(expected)
		sort.Strings(groups)
		if !reflect.DeepEqual(groups, expected) {
			t.Fatalf("'%+v' groups expected to be '%+v', got '%+v'", TestUser1.CommonName, expected, groups)
		}
	}
	t.Logf("Checking '%+v' memberof", TestUser2.CommonName)
	if groups, err := GetUserGroups(TestUser2.ShortName); err != nil {
		t.Fatalf("Failed to GetUserGroups('%+v') - '%+v'", TestUser2.ShortName, err)
	} else {
		expected := []string{TestGroup2.CommonName}
		sort.Strings(expected)
		sort.Strings(groups)
		if !reflect.DeepEqual(groups, expected) {
			t.Fatalf("'%+v' groups expected to be '%+v', got '%+v'", TestUser2.CommonName, expected, groups)
		}
	}

	t.Logf("Checking '%+v' membership", TestGroup1.CommonName)
	if users, err := GetUsersInGroup(TestGroup1.CommonName); err != nil {
		t.Fatalf("Failed to GetUsersInGroup('%+v') - '%+v'", TestGroup1.ShortName, err)
	} else {
		expected := []string{TestUser1.ShortName}
		sort.Strings(expected)
		sort.Strings(users)
		if !reflect.DeepEqual(users, expected) {
			t.Fatalf("'%+v' users expected to be '%+v', got '%+v'", TestGroup1.CommonName, expected, users)
		}
	}
	t.Logf("Checking '%+v' membership", TestGroup2.CommonName)
	if users, err := GetUsersInGroup(TestGroup2.CommonName); err != nil {
		t.Fatalf("Failed to GetUsersInGroup('%+v') - '%+v'", TestGroup2.ShortName, err)
	} else {
		expected := []string{TestUser1.ShortName, TestUser2.ShortName}
		sort.Strings(expected)
		sort.Strings(users)
		if !reflect.DeepEqual(users, expected) {
			t.Fatalf("'%+v' users expected to be '%+v', got '%+v'", TestGroup2.CommonName, expected, users)
		}
	}

	t.Logf("Removing '%+v' from '%+v'", TestUser1.CommonName, TestGroup2.CommonName)
	if err := GroupRemoveUser(TestGroup2.ShortName, TestUser1.ShortName); err != nil {
		t.Fatalf("Failed to GroupRemoveUser('%+v', '%+v') - '%+v'", TestGroup2.ShortName, TestUser1.ShortName, err)
	}
	t.Logf("Checking '%+v' membership", TestGroup2.CommonName)
	if users, err := GetUsersInGroup(TestGroup2.CommonName); err != nil {
		t.Fatalf("Failed to GetUsersInGroup('%+v') - '%+v'", TestGroup2.ShortName, err)
	} else {
		expected := []string{TestUser2.ShortName}
		sort.Strings(expected)
		sort.Strings(users)
		if !reflect.DeepEqual(users, expected) {
			t.Fatalf("'%+v' users expected to be '%+v', got '%+v'", TestGroup2.CommonName, expected, users)
		}
	}
}
