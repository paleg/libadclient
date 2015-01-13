/* 
   C++ Active Directory manipulation class.
   Based on adtool by Mike Dawson (http://gp2x.org/adtool/).
*/

#include <ldap.h>

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

#define AD_SUCCESS 1
#define AD_LDAP_CONNECTION_ERROR 2
#define AD_PARAMS_ERROR 2
#define AD_SERVER_CONNECT_FAILURE 4
#define AD_OBJECT_NOT_FOUND 6
#define AD_ATTRIBUTE_ENTRY_NOT_FOUND 7
#define AD_OU_SYNTAX_ERROR 8
#define MAX_PASSWORD_LENGTH 22
#define AD_SCOPE_BASE LDAP_SCOPE_BASE
#define AD_SCOPE_SUBTREE LDAP_SCOPE_SUBTREE

using namespace std;

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

      void login(string uri, string binddn, string bindpw, string _search_base);

      void groupAddUser(string group, string user);
      void groupRemoveUser(string group, string user);
      void CreateUser(string cn, string container, string user_short);
      void DeleteDN(string dn);
      void CreateOU(string ou);
      void UnLockUser(string user);

      void setUserPassword(string user, string password);
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
      void UnlockUser(string user);

      string          getObjectDN(string object_short);
      string          getUserDisplayName(string user);

      bool            ifDialinUser(string user);
      bool            ifUserDisabled(string user);
      bool            ifObjectExists(string object);

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

      vector <string> searchDN_ext(string filter);
      map < string, map < string, vector<string> > > search_ext(string OU, int scope, string filter, vector <string> attributes);

      vector < pair <string, vector <string> > > getObjectAttributes(string object);
private:
      string search_base;
      LDAP *ds;
      int scope;

      void mod_add(string object, string attribute, string value);
      void mod_delete(string object, string attribute, string value);
      void mod_replace(string object, string attribute, string value);
      map < string, vector<string> > _getvalues(LDAPMessage *entry, vector <string> attributes);
      string itos(int num);
      string dn2domain(string dn);
};
