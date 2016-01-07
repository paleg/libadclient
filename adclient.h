/* 
   C++ Active Directory manipulation class.
   Based on adtool by Mike Dawson (http://gp2x.org/adtool/).
*/

#ifndef _ADCLIENT_H_
#define _ADCLIENT_H_

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
#include <climits>
#include <cerrno>
#include <cstdlib>
#include <resolv.h>

// for OS X
#ifndef NS_MAXMSG
#define NS_MAXMSG 65535
#include <arpa/nameser_compat.h>
#endif

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
      void login(std::vector <string> uries, string binddn, string bindpw, string _search_base, bool secured = true);

      string binded_uri() { return uri; }

      void groupAddUser(string group, string user);
      void groupRemoveUser(string group, string user);
      void CreateUser(string cn, string container, string user_short);
      void CreateGroup(string cn, string container, string group_short);
      void CreateOU(string ou);
      void DeleteDN(string dn);
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
      void setUserIpAddress(string user, string ip);

      void setObjectAttribute(string user, string attr, string ip);

      std::map <string, bool>    getUserControls(string user);

      bool                  getUserControl(string user, string control);

      bool                  ifUserExpired(string user);
      bool                  ifUserLocked(string user);
      bool                  ifUserDisabled(string user);
      bool                  ifUserMustChangePassword(string user);
      bool                  ifUserDontExpirePassword(string user);

      string          getObjectDN(string object);
      string          getUserDisplayName(string user);
      string          getUserIpAddress(string user);

      bool            ifDialinUser(string user);

      bool            ifDNExists(string object, string objectclass);
      bool            ifDNExists(string object);

      std::vector <string> getGroups();
      std::vector <string> getUsers();
      std::vector <string> getAllOUs();
      std::vector <string> getDialinUsers();
      std::vector <string> getDisabledUsers();

      std::vector <string> getUserGroups(string user);
      std::vector <string> getUsersInGroup(string group);
      std::vector <string> getOUsInOU(string OU);
      std::vector <string> getUsersInOU(string OU);
      std::vector <string> getUsersInOU_SubTree(string OU);

      struct berval getBinaryObjectAttribute(string object, string attribute);
      std::vector <string> getObjectAttribute(string object, string attribute);

      std::vector <string> searchDN(string filter);
      std::map < string, std::map < string, std::vector<string> > > search(string OU, int scope, string filter, const std::vector <string> &attributes);

      std::map <string, std::vector <string> > getObjectAttributes(string object);
      std::map <string, std::vector <string> > getObjectAttributes(string object, const std::vector<string> &attributes);

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
      std::map < string, std::vector<string> > _getvalues(LDAPMessage *entry);
      string dn2domain(string dn);
      std::vector <string> DNsToShortNames(std::vector <string> &v);
      std::vector<string> get_ldap_servers(string domain);
};

inline string vector2string(const std::vector<string> &v) {
    std::stringstream ss;
    for(size_t i = 0; i < v.size(); ++i) {
        if (i != 0) ss << ",";
        ss << v[i];
    }
    return ss.str();
}

// ft is the number of 100-nanosecond intervals since January 1, 1601 (UTC)
inline time_t FileTimeToPOSIX(long long ft) {
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

inline void replace(std::string& subject, const std::string& search,
                                   const std::string& replace) {
    size_t pos = 0;
    while((pos = subject.find(search, pos)) != std::string::npos) {
         subject.replace(pos, search.length(), replace);
         pos += replace.length();
    }
}

inline string itos(int num) {
    std::stringstream ss;
    ss << num;
    return(ss.str());
}

inline long long stol(string s) {
   errno = 0;
   char *endptr;
   int base = 10;
   long long val = strtoll(s.c_str(), &endptr, base);
   if ((errno == ERANGE && (val == LLONG_MAX || val == LLONG_MIN))
      || (errno != 0 && val == 0)) {
      throw std::invalid_argument("unacceptable input: " + s);
   }
   string end = string(endptr);
   if (end.size() != 0) {
      throw std::invalid_argument("invalid input: " + end);
   }
   return val;
}

inline string DecToBin(long long number) {
    if ( number == 0 ) return "0";
    if ( number == 1 ) return "1";

    if ( number % 2 == 0 )
        return DecToBin(number / 2) + "0";
    else
        return DecToBin(number / 2) + "1";
}

inline long long BinToDec(string number) {
    long long result = 0, pow = 1;
    for ( int i = number.length() - 1; i >= 0; --i, pow <<= 1 )
        result += (number[i] - '0') * pow;

    return result;
}

inline int ip2int(string ip) {
    string ipbin = "";
    std::istringstream iss(ip);
    string s;
    int iters = 0;
    while (getline(iss, s, '.')) {
        string bin = DecToBin(stol(s));
        if (bin.size() > 8) {
            throw std::invalid_argument("wrong ipv4 address: " + ip);
            break;
        } else if (bin.size() < 8) {
            while (bin.size() != 8) {
                bin = "0" + bin;
            }
        }
        ipbin = ipbin + bin;
        iters++;
    }
    if (iters != 4) {
        throw std::invalid_argument("wrong ipv4 address: " + ip);
    }
    long long ipdec = BinToDec(ipbin);
    if (ipdec > 2147483647) {
        ipdec = ipdec - 4294967296;
    }
    return ipdec;
}

inline string int2ip(string value) {
    long long intip = stol(value);
    if (intip < 0) {
        intip += 4294967296L;
    }
    string binip = DecToBin(intip);
    if (binip.size() > 32) {
        throw std::invalid_argument("wrong value: " + binip);
    } else if (binip.size() < 32) {
        while (binip.size() != 32) {
            binip = "0" + binip;
        }
    }
    string firstOctet = binip.substr(0, 8);
    string secondOctet = binip.substr(8, 8);
    string thirdOctet = binip.substr(16, 8);
    string fourthOctet = binip.substr(24, 8);
    string ip = itos(BinToDec(firstOctet)) + ".";
    ip += itos(BinToDec(secondOctet)) + ".";
    ip += itos(BinToDec(thirdOctet)) + ".";
    ip += itos(BinToDec(fourthOctet));
    return ip;
}

#endif // _ADCLIENT_H_
