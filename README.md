# libadclient
Active Directory client for c++ and python

Requirements: openldap or SunLDAP

DESCRIPTION:
  This simple C++/Python classes can be used to manipulate Active Directory from c++ or Python programs.
  This module reuses some code from adtool by Mike Dawson.

INSTALL (*nix):

Note: you must have scons installed

  1. $ git clone https://github.com/paleg/libadclient.git
  2. $ cd libadclient
  3. $ scons install (to build/install c++ library)
  4. $ python setup.py install (to build/install python library)

Note: step 4 depends on step 3. So if your want to upgrade python module, you should upgrade c++ library first. 

Full list of supported methods can be found in [adclient.h](https://github.com/paleg/libadclient/blob/master/adclient.h) (for c++) and [adclient.py](https://github.com/paleg/libadclient/blob/master/adclient.py) (for python)

USAGE SAMPLE (c++):
```
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
        ad.login(uries, "user@domain.com", "password", "dc=xx,dc=xx,dc=xx,dc=xx");
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
```
import adclient
ad = adclient.ADClient()
try:
  ad.login(["ldap://Server1", "ldap://Server2", "ldap://Server3"], "user@domain.com", "password", "dc=xx,dc=xx,dc=xx,dc=xx")
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
