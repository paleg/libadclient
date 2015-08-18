/* 
   C++ Active Directory manipulation class.
   Based on adtool by Mike Dawson (http://gp2x.org/adtool/).
*/

#include <ldap.h>
#include <sasl/sasl.h>

#if defined( OPENLDAP )
	#define LDAPOPTSUCCESS LDAP_OPT_SUCCESS
#elif defined( SUNLDAP )
	#define LDAPOPTSUCCESS LDAP_SUCCESS
#endif

/*#include <mpatrol.h>*/
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <iostream>
#include <iterator>     // std::distance
#include <stdexcept>    // std::out_of_range
#include <ctime>
#include <limits>
#include <resolv.h>

#define AD_SUCCESS                      1
#define AD_LDAP_CONNECTION_ERROR        2
#define AD_PARAMS_ERROR                 4
#define AD_SERVER_CONNECT_FAILURE       6
#define AD_OBJECT_NOT_FOUND             8
#define AD_ATTRIBUTE_ENTRY_NOT_FOUND    10
#define AD_OU_SYNTAX_ERROR              12
#define AD_LDAP_RESOLV_ERROR            14

#define MAX_PASSWORD_LENGTH 22

#define AD_SCOPE_BASE       LDAP_SCOPE_BASE
#define AD_SCOPE_ONELEVEL   LDAP_SCOPE_ONELEVEL
#define AD_SCOPE_SUBTREE    LDAP_SCOPE_SUBTREE

using std::vector;
using std::map;
using std::string;
using std::cout;
using std::endl;

struct sasl_defaults {
    string username;
    string password;
};

class ADException {
public:
      ADException(string _msg, int _code) { msg = _msg; code = _code; }
      int code;
      string msg;
};

class ADBindException: public ADException {
public:
      ADBindException(string _msg, int _code): ADException(_msg, _code) {}
};

class ADSearchException: public ADException {
public:
      ADSearchException(string _msg, int _code): ADException(_msg, _code) {}
};

class ADOperationalException: public ADException {
public:
      ADOperationalException(string _msg, int _code): ADException(_msg, _code) {}
};

class adclient {
public:
      adclient();
      ~adclient();

      void login(string uri, string binddn, string bindpw, string _search_base, bool secured = true);
      void login(vector <string> uries, string binddn, string bindpw, string _search_base, bool secured = true);

      string binded_uri() { return uri; }

      void groupAddUser(string group, string user);
      void groupRemoveUser(string group, string user);
      void CreateUser(string cn, string container, string user_short);
      void DeleteDN(string dn);
      void CreateOU(string ou);
      void EnableUser(string user);
      void DisableUser(string user);
      void UnLockUser(string user);

      void setUserPassword(string user, string password);
      bool checkUserPassword(string user, string password);
      void setUserDialinAllowed(string user);
      void setUserDialinDisabled(string user);
      void setUserSN(string user, string sn);
      void setUserInitials(string user, string initials);
      void setUserGivenName(string user, string givenName);
      void setUserDisplayName(string user, string displayName);
      void setUserRoomNumber(string user, string roomNum);
      void setUserAddress(string user, string streetAddress);
      void setUserInfo(string user, string info);
      void setUserTitle(string user, string title);
      void setUserDepartment(string user, string department);
      void setUserCompany(string user, string company);
      void setUserPhone(string user, string phone);
      void setUserDescription(string user, string descr);

      map <string, bool>    getUserControls(string user);

      bool                  getUserControl(string user, string control);

      bool                  ifUserExpired(string user);
      bool                  ifUserLocked(string user);
      bool                  ifUserDisabled(string user);
      bool                  ifUserMustChangePassword(string user);
      bool                  ifUserDontExpirePassword(string user);

      string          getObjectDN(string object);
      string          getUserDisplayName(string user);

      bool            ifDialinUser(string user);

      bool            ifDNExists(string object, string objectclass);
      bool            ifDNExists(string object);

      vector <string> getGroups();
      vector <string> getUsers();
      vector <string> getAllOUs();
      vector <string> getDialinUsers();

      vector <string> getUserGroups(string user);
      vector <string> getUsersInGroup(string group);
      vector <string> getOUsInOU(string OU);
      vector <string> getUsersInOU(string OU);
      vector <string> getUsersInOU_SubTree(string OU);

      struct berval getBinaryObjectAttribute(string object, string attribute);
      vector <string> getObjectAttribute(string object, string attribute);

      vector <string> searchDN(string filter);
      map < string, map < string, vector<string> > > search(string OU, int scope, string filter, const vector <string> &attributes);

      map <string, vector <string> > getObjectAttributes(string object);
      map <string, vector <string> > getObjectAttributes(string object, const vector<string> &attributes);

      // LDAP_OPT_NETWORK_TIMEOUT, LDAP_OPT_TIMEOUT
      int nettimeout;
      // LDAP_OPT_TIMELIMIT
      int timelimit;
private:
      string uri;
      string search_base;
      LDAP *ds;
      int scope;
      string ldap_prefix;

      void login(LDAP **ds, string uri, string binddn, string bindpw, string _search_base, bool secured);
      void logout(LDAP *ds);

      void mod_add(string object, string attribute, string value);
      void mod_delete(string object, string attribute, string value);
      void mod_replace(string object, string attribute, string value);
      map < string, vector<string> > _getvalues(LDAPMessage *entry);
      string itos(int num);
      string dn2domain(string dn);
      vector <string> DNsToShortNames(vector <string> &v);
      vector<string> get_ldap_servers(string domain);
};

string vector2string(const vector<string> &v) {
    std::stringstream ss;
    for(size_t i = 0; i < v.size(); ++i) {
        if (i != 0) ss << ",";
        ss << v[i];
    }
    return ss.str();
}

// ft is the number of 100-nanosecond intervals since January 1, 1601 (UTC)
time_t FileTimeToPOSIX(long long ft) {
    // never expired
    if (ft == 0) {
        ft = 9223372036854775807;
    }

    long long result;
    // Between Jan 1, 1601 and Jan 1, 1970 there are 11644473600 seconds
    // 100-nanoseconds = milliseconds * 10000 = seconds * 1000 * 10000
    result = ft - 11644473600 * 1000 * 10000;
    // convert back from 100-nanoseconds to seconds
    result = result / 10000000;
    if (result > std::numeric_limits<time_t>::max()) {
        return std::numeric_limits<time_t>::max();
    } else {
        return result;
    }
}

void replace(std::string& subject, const std::string& search,
                                   const std::string& replace) {
    size_t pos = 0;
    while((pos = subject.find(search, pos)) != std::string::npos) {
         subject.replace(pos, search.length(), replace);
         pos += replace.length();
    }
}
