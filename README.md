# libadclient
Active Directory client for c++, Python and Golang

Requirements: openldap or SunLDAP

DESCRIPTION:
  This simple C++/Python/Golang classes can be used to manipulate Active Directory from c++, Python and Golang programs.
  
  This module reuses some code from adtool by Mike Dawson.

INSTALL (c++ and Python):

Note: you must have [scons](http://www.scons.org/) installed

  1. $ git clone https://github.com/paleg/libadclient.git
  2. $ cd libadclient
  3. $ scons install (to build/install c++ library)
  4. $ python setup.py install (to build/install python library)

Note: step 4 depends on step 3. So if your want to upgrade python module, you should upgrade c++ library first. 

OS X 10.11 INSTALL NOTE:

If you are getting errors in python while importing module:
```
ImportError: dlopen(/Library/Python/2.7/site-packages/_adclient.so, 2): Library not loaded: libadclient.dylib
  Referenced from: /Library/Python/2.7/site-packages/_adclient.so
  Reason: unsafe use of relative rpath libadclient.dylib in /Library/Python/2.7/site-packages/_adclient.so with restricted binary
```
that is because [System Integrity Protection](https://support.apple.com/en-us/HT204899). You can fix it with:
```
$ sudo install_name_tool -change libadclient.dylib /usr/local/lib/libadclient.dylib /Library/Python/2.7/site-packages/_adclient.so
```

INSTALL (Golang):
```
 $ go get github.com/paleg/libadclient
```
You must have swig >= 3.0.6 and Golang >= 1.4 to compile library. However, Golang >= 1.5.1 is recommended.
When building Golang library only openldap >= 2.2 are supported.

Note: this library is not safe for concurrent use. If you need to use library from concurrently executing goroutines, the calls must be mediated by some kind of synchronization mechanism (channels or mutexes).


Full list of supported methods can be found in [adclient.h](https://github.com/paleg/libadclient/blob/master/adclient.h) (for c++) and [adclient.py](https://github.com/paleg/libadclient/blob/master/adclient.py) (for python)

USAGE NOTES:

login: 
  - Login can be performed with SASL DIGEST-MD5 auth (default) or simple auth (clear text username and password). The last boolean argument `secured` in login function chooses login mode.
  - SASL DIGEST-MD5 auth requires properly configured DNS (both direct and reverse) and SPN records (see [issue 1](https://github.com/paleg/libadclient/issues/1#issuecomment-131693081) for details). 
  - Simple auth does not require all this things, but with simple auth AD will refuse to do some actions (e.g. change passwords).
  - Login can be performed with a vector (list) of ldap uries, single ldap uri or domain DNS name. Ldap uries must be prefixed with `ldap://`. Single values without ldap prefix are treated as a domain name and ldap uries are detected via DNS SRV query (_ldap._tcp.xx.xx.xx.xx).

USAGE SAMPLE (c++):
```cpp
#include "adclient.h"
#include <iostream>
#include <vector>
#include <map>
#include <string>

using namespace std;

int main() {
    adclient ad;

    vector <string> uries;
    uries.push_back("ldap://Server1");
    uries.push_back("ldap://Server2");
    uries.push_back("ldap://Server3");
    try {
        // secured SASL login with a list of ldap uries
        ad.login(uries, "user", "password", "dc=xx,dc=xx,dc=xx,dc=xx");
        // simple auth with a single ldap server uri
        //ad.login("ldap://Server1", "user", "password", "dc=xx,dc=xx,dc=xx,dc=xx", false);
        // secured SASL login with a domain name
        //ad.login("xx.xx.xx.xx", "user", "password", "dc=xx,dc=xx,dc=xx,dc=xx", true)
    }
    catch(ADBindException& ex) {
         cout << "ADBindLogin: " << ex.msg << endl;
         return 1;
    }
    try {
        ad.groupRemoveUser("Group", "User");
        vector <string> user_groups = ad.getUserGroups("User");
        vector <string> users_in_group = ad.getUsersInGroup("Groups");
        vector <string> user_lastlogon = ad.getObjectAttribute("User", "lastLogon");
        map <string, vector<string> > user_attrs = ad.getObjectAttributes("User");
        vector <string> users = ad.getUsers();
        string dn = ad.getObjectDN("User");
        bool result = ad.checkUserPassword("User", "Password");
        bool disabled = ad.ifUserDisabled("User");
        bool locked = ad.ifUserLocked("User");
    }
    catch (const ADOperationalException& ex) {
      cout << "ADOperationalException: " << ex.msg << endl;
    }
    catch (const ADSearchException& ex) {
      cout << "ADSearchException: " << ex.msg << endl;
    }

   return 0;
}
```

USAGE SAMPLE (python):
```python
import adclient
ad = adclient.ADClient()
try:
  # secured SASL login with a list of ldap uries
  ad.login(["ldap://Server1", "ldap://Server2", "ldap://Server3"], "user", "password", "dc=xx,dc=xx,dc=xx,dc=xx")
  # simple auth with a single ldap server uri
  #ad.login("ldap://Server1", "user", "password", "dc=xx,dc=xx,dc=xx,dc=xx", False)
  # secured SASL login with a domain name
  #ad.login("xx.xx.xx.xx", "user", "password", "dc=xx,dc=xx,dc=xx,dc=xx", True)
except ADBindError, ex:
  print("failed to connect to Active Directory: %s"%(ex))
  exit(1)
  
try:
  dn = ad.getObjectDN("User");
except adclient.ADSearchError, ex:
  code = ad.get_error_num()
  if code == adclient.AD_OBJECT_NOT_FOUND:
    print("no such user")
  else:
    print("unknown search error")
except ADOperationalError:
  print("unknown operational error")
```

USAGE SAMPLE (Golang):
```go
package main

import (
  "github.com/paleg/libadclient"
  "fmt"
)

func main() {
  adclient.New()
  defer adclient.Delete()
  
  adclient.Timelimit = 60
  adclient.Nettimeout = 60
  // secured SASL login with a list of ldap uries
  // if err : =ad.login(["ldap://Server1", "ldap://Server2", "ldap://Server3"], "user", "password", "dc=xx,dc=xx,dc=xx,dc=xx"), err != nil {
  // secured SASL login with a domain name
  if err := adclient.Login("xx.xx.xx.xx", "user", "password", "dc=xx,dc=xx,dc=xx,dc=xx"); err != nil {
    fmt.Printf("Failed to AD login: %v\n", err)
    return
  }
  
  group := "Domain Admins"
  if users, err := adclient.GetUsersInGroup(group); err != nil {
    fmt.Printf("Failed to get users in '%v': %v\n", group, err)
  } else {
    fmt.Printf("Users in '%v':\n", group)
    for _, user := range users {
      fmt.Printf("\t%v\n", user)
    }
  }
}
```
