#include "stdlib.h"
#include "adclient.h"

adclient::adclient() {
/*
  Constructor, to initialize default values of global variables.
*/
    ds = NULL;
    scope = LDAP_SCOPE_SUBTREE;
}

adclient::~adclient() {
/*
  Destructor, to automaticaly free initial values allocated at login().
*/
    if (ds != NULL)
    ldap_unbind_ext(ds, NULL, NULL);
}

void adclient::login(string uri, string binddn, string bindpw, string _search_base) {
/*
  To set various LDAP options and bind to LDAP server.
  It set private pointer to LDAP connection identifier - ds.
  It returns nothing if operation was successfull, throws ADBindException otherwise.
*/
    int result, version, bindresult;

    struct berval cred;
    struct berval *servcred;

    cred.bv_val = strdup(bindpw.c_str());
    cred.bv_len = bindpw.size();
	
    string error_msg;

    search_base = _search_base;

#if defined OPENLDAP 
    result = ldap_initialize(&ds, uri.c_str());
#elif defined SUNLDAP
    result = ldapssl_init(uri.c_str(), LDAPS_PORT, 1);
#endif
    if (result != LDAP_SUCCESS) {
        error_msg = "Error in ldap_initialize to " + uri + ": ";
        error_msg.append(ldap_err2string(result));
        throw ADBindException(error_msg, AD_SERVER_CONNECT_FAILURE);
    }

    version = LDAP_VERSION3;
    result = ldap_set_option(ds, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (result != LDAP_OPT_SUCCESS) {
        error_msg = "Error in ldap_set_option (protocol->v3): ";
        error_msg.append(ldap_err2string(result));
        throw ADBindException(error_msg, AD_SERVER_CONNECT_FAILURE);
    }

    result = ldap_set_option(ds, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    if (result != LDAP_OPT_SUCCESS) {
        error_msg = "Error in ldap_set_option (referrals->off): ";
        error_msg.append(ldap_err2string(result));
        throw ADBindException(error_msg, AD_SERVER_CONNECT_FAILURE);
    }

    bindresult = ldap_sasl_bind_s(ds, binddn.c_str(), NULL, &cred, NULL, NULL, &servcred);

    memset(cred.bv_val, 0, cred.bv_len);
    free(cred.bv_val);

    if (bindresult != LDAP_SUCCESS) {
        error_msg = "Error while ldap binding with " + binddn + " " + bindpw + ": ";
        error_msg.append(ldap_err2string(bindresult));
        throw ADBindException(error_msg, AD_SERVER_CONNECT_FAILURE);
    }
}

vector <string> adclient::searchDN_ext(string filter) {
/*
  General search function.
  It returns vector of DNs, which match the given attribute and value,
     throws ADSearchException - if error occupied.
*/
    int result, num_results, i;
    char *attrs[]={"1.1", NULL};
    LDAPMessage *res = NULL;
    LDAPMessage *entry;
    char *dn;
    vector <string> dnlist;
    string error_msg;
    int attrsonly = 1;

    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    result = ldap_search_ext_s(ds, search_base.c_str(), scope, filter.c_str(), attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
    if (result != LDAP_SUCCESS) {
       if (res != NULL) ldap_msgfree(res);
       error_msg = "Error in ldap_search_ext_s: ";
       error_msg.append(ldap_err2string(result));
       throw ADSearchException(error_msg, result);
    }

    num_results = ldap_count_entries(ds, res);
    if (num_results == 0) {
        ldap_msgfree(res);
        error_msg = filter + " not found";
        throw ADSearchException(error_msg, AD_OBJECT_NOT_FOUND);
    }

    entry = ldap_first_entry(ds, res);
    dn = ldap_get_dn(ds, entry);
    dnlist.push_back(dn);
    ldap_memfree(dn);

    for (i=1; (entry=ldap_next_entry(ds, entry))!=NULL; i++) {
        dn = ldap_get_dn(ds, entry);
        dnlist.push_back(dn);
        ldap_memfree(dn);
    }

    ldap_msgfree(res);
    return dnlist;
}

string adclient::getObjectDN(string object_short) {
/*
  It returns string with DN of object_short.
  Can throw ADSearchException (from called functions).
*/
    vector <string> dn;

    string filter = "(sAMAccountName=" + object_short + ")";
    dn = searchDN_ext(filter);
    return dn[0];
}

struct berval adclient::getBinaryObjectAttribute(string object, string attribute) {
/* 
  It returns vector of strings with one entry for each attribute/value pair,
  throws ADSearchException if no values were found, or if error occupied.
*/
    int result, num_entries;
    char *attrs[2];
    LDAPMessage *res=NULL;
    LDAPMessage *entry;
    struct berval value; 

    string error_msg;

    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    string dn;

    try {
        dn = getObjectDN(object);
    }
    catch (ADSearchException) {
        dn = object;
    }

    attrs[0] = strdup(attribute.c_str());
    attrs[1] = NULL;
    result = ldap_search_ext_s(ds, dn.c_str(), LDAP_SCOPE_BASE, "(objectclass=*)", attrs, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
    free(attrs[0]);
    if (result != LDAP_SUCCESS) {
        if (res != NULL) ldap_msgfree(res);
        error_msg = "Error in ldap_search_ext_s for getObjectAttribute: ";
        error_msg.append(ldap_err2string(result));
        throw ADSearchException(error_msg, result);
    }
    num_entries=ldap_count_entries(ds, res);
    if (num_entries == 0) {
        error_msg = "No entries found in getObjectAttribute for user " + dn;
        ldap_msgfree(res);
        throw ADSearchException(error_msg, AD_OBJECT_NOT_FOUND);
    } else if (num_entries > 1) {
        error_msg = "More than one entry found in getObjectAttribute for user " + dn;
        ldap_msgfree(res);
        throw ADSearchException(error_msg, AD_OBJECT_NOT_FOUND);
    }

    entry=ldap_first_entry(ds, res);
    struct berval **_values;
    _values=ldap_get_values_len(ds, entry, attribute.c_str());
    if (_values == NULL) {
       error_msg = "Error in ldap_get_values_len for getObjectAttribute: no values found for attribute " + attribute + " in object " + dn;
        ldap_msgfree(res);
        throw ADSearchException(error_msg, AD_ATTRIBUTE_ENTRY_NOT_FOUND);
    }
    for (int i=0; _values[i]!=NULL; i++) {
        value = *_values[i];
    }
    ldap_value_free_len(_values);
    ldap_msgfree(res);
    return value;
}

map < string, map < string, vector<string> > > adclient::search_ext(string OU, int scope, string filter, vector <string> attributes) {
    int result, num_entries;
    char *attrs[50];
    LDAPMessage *res=NULL;
    LDAPMessage *entry;

    string error_msg;

    if (attributes.size() > 50) throw ADSearchException("Cant return more than 50 attributes", AD_PARAMS_ERROR);

    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    unsigned int i;
    for (i=0; i<attributes.size(); i++) {
        attrs[i] = strdup(attributes[i].c_str());
    }
    attrs[i] = NULL;
//    char *attrs[]={"1.1", NULL};
//    result = ldap_search_ext_s(ds, OU.c_str(), LDAP_SCOPE_BASE, filter.c_str(), attrs, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
    result = ldap_search_ext_s(ds, OU.c_str(), scope, filter.c_str(), attrs, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);

    for (i=0; i<attributes.size(); i++) {
        free(attrs[i]);
    }

    if (result != LDAP_SUCCESS) {
        if (res != NULL) ldap_msgfree(res);
        error_msg = "Error in ldap_search_ext_s for search_ext: ";
        error_msg.append(ldap_err2string(result));
        throw ADSearchException(error_msg, result);
    }

    int num_results = ldap_count_entries(ds, res);
    if (num_results == 0) {
        ldap_msgfree(res);
        error_msg = filter + " not found";
        throw ADSearchException(error_msg, AD_OBJECT_NOT_FOUND);
    }

/*    dn = ldap_get_dn(ds, entry);
    dnlist.push_back(dn);
    ldap_memfree(dn);

    for (i=1; (entry=ldap_next_entry(ds, entry))!=NULL; i++) {
        dn = ldap_get_dn(ds, entry);
        dnlist.push_back(dn);
        ldap_memfree(dn);
    }

    ldap_msgfree(res);
    return dnlist;

*/
    char *dn;
    map < string, vector<string> > valuesmap;
    map < string, map < string, vector<string> > > search_result;

    entry = ldap_first_entry(ds, res);
    dn = ldap_get_dn(ds, entry);
    valuesmap = _getvalues(entry, attributes);
    search_result[dn] = valuesmap;
    ldap_memfree(dn);
    
    while ((entry=ldap_next_entry(ds, entry))!=NULL) {
        dn = ldap_get_dn(ds, entry);
        valuesmap = _getvalues(entry, attributes);
        search_result[dn] = valuesmap;
        ldap_memfree(dn);
    }
    ldap_msgfree(res);
    return search_result;
}

map < string, vector<string> > adclient::_getvalues(LDAPMessage *entry, vector <string> attributes) {
    if ((ds == NULL) || (entry == NULL)) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    map < string, vector<string> > result;
    for (unsigned int i=0; i<attributes.size(); i++) {
       vector <string> values;
       struct berval **_values;
       _values=ldap_get_values_len(ds, entry, attributes[i].c_str());
       if (_values == NULL) {
           /*error_msg = "Error in ldap_get_values_len for search_ext: no values found for attribute " + attributes[i] + " in object " + dn;
           ldap_msgfree(res);
           throw ADSearchException(error_msg, AD_ATTRIBUTE_ENTRY_NOT_FOUND);*/
           ldap_value_free_len(_values);
           continue;
       }
       struct berval data;
       for (unsigned int j=0; _values[j]!=NULL; j++) {
           data = *_values[j];
           values.push_back(data.bv_val);
       }
       ldap_value_free_len(_values);
       result[attributes[i]] = values;
    }
    return result;
}

vector <string> adclient::getObjectAttribute(string object, string attribute) {
/* 
  It returns vector of strings with one entry for each attribute/value pair,
  throws ADSearchException if no values were found, or if error occupied.
*/
    int result, num_entries;
    char *attrs[2];
    LDAPMessage *res=NULL;
    LDAPMessage *entry;

    vector <string> values;
    string error_msg;

    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    string dn;

    try {
        dn = getObjectDN(object);
    }
    catch (ADSearchException) {
        dn = object;
    }

    attrs[0] = strdup(attribute.c_str());
    attrs[1] = NULL;
    result = ldap_search_ext_s(ds, dn.c_str(), LDAP_SCOPE_BASE, "(objectclass=*)", attrs, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
    free(attrs[0]);
    if (result != LDAP_SUCCESS) {
        if (res != NULL) ldap_msgfree(res);
        error_msg = "Error in ldap_search_ext_s for getObjectAttribute: ";
        error_msg.append(ldap_err2string(result));
        throw ADSearchException(error_msg, result);
    }

    num_entries=ldap_count_entries(ds, res);
    if (num_entries == 0) {
        error_msg = "No entries found in getObjectAttribute for user " + dn;
        ldap_msgfree(res);
        throw ADSearchException(error_msg, AD_OBJECT_NOT_FOUND);
    } else if (num_entries > 1) {
        error_msg = "More than one entry found in getObjectAttribute for user " + dn;
        ldap_msgfree(res);
        throw ADSearchException(error_msg, AD_OBJECT_NOT_FOUND);
    }

    entry=ldap_first_entry(ds, res);
    struct berval **_values;
    _values=ldap_get_values_len(ds, entry, attribute.c_str());
    if (_values == NULL) {
        error_msg = "Error in ldap_get_values_len for getObjectAttribute: no values found for attribute " + attribute + " in object " + dn;
        ldap_msgfree(res);
        throw ADSearchException(error_msg, AD_ATTRIBUTE_ENTRY_NOT_FOUND);
    }
    struct berval data;
    for (int i=0; _values[i]!=NULL; i++) {
        data = *_values[i];
        values.push_back(data.bv_val);
    }
    ldap_value_free_len(_values);
    ldap_msgfree(res);
    return values;
}

vector < pair <string, vector <string> > >  adclient::getObjectAttributes(string object) {
/*
  It returns vector of pair's: attribute - vector of values, with all object attributes
  throws ADSearchException if no values were found, or if error occupied.
*/
    int result, num_results, i;
    char *attrs[]={"*", NULL};
    LDAPMessage *res;
    LDAPMessage *entry;
    string error_msg;
    int attrsonly = 0;
    vector < pair < string, vector <string> > > attributes;
    vector <string> temp;
    BerElement *berptr;
    char *next;

    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    string dn;

    try {
        dn = getObjectDN(object);
    }
    catch (ADSearchException) {
        dn = object;
    }

    string filter = "(objectclass=*)";
    result = ldap_search_ext_s(ds, dn.c_str(), scope, filter.c_str(), attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
    if (result != LDAP_SUCCESS) {
        error_msg = "Error in ldap_search_ext_s: ";
        error_msg.append(ldap_err2string(result));
        throw ADSearchException(error_msg, result);
    }

    num_results = ldap_count_entries(ds, res);
    if (num_results == 0) {
        ldap_msgfree(res);
        error_msg = filter + " not found";
        throw ADSearchException(error_msg, AD_OBJECT_NOT_FOUND);
    }

    entry = ldap_first_entry(ds, res);

    next = ldap_first_attribute(ds, entry, &berptr);
    struct berval **values;
    struct berval data;
    values = ldap_get_values_len(ds, entry, next);
    for (i=0; values[i] != NULL; i++) {
        data = *values[i];
        temp.push_back(data.bv_val);
    }
    attributes.push_back(make_pair(next, temp));
    temp.clear();
    ldap_memfree(next);
    ldap_value_free_len(values);

    while ((next = ldap_next_attribute(ds, entry, berptr)) != NULL) {
        values = ldap_get_values_len(ds, entry, next);
        for (i=0; values[i] != NULL; i++) {
            data = *values[i];
            temp.push_back(data.bv_val);
        }
        attributes.push_back(make_pair(next, temp));
        temp.clear();
        ldap_memfree(next);
        ldap_value_free_len(values);
    }

    ber_free(berptr, 0);
    ldap_msgfree(res);
    return attributes;
}

bool adclient::ifObjectExists(string object) {
    int result;
    char *attrs[]={"*", NULL};
    LDAPMessage *res;
    string error_msg;
    int attrsonly = 1;

    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    string dn;

    try {
        dn = getObjectDN(object);
    }
    catch (ADSearchException) {
        dn = object;
    }

    string filter = "(objectclass=*)";
    result = ldap_search_ext_s(ds, dn.c_str(), scope, filter.c_str(), attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
    ldap_msgfree(res);

    if (result != LDAP_SUCCESS) {
	return false;
    } else {
	return true;
    }
}

void adclient::groupAddUser(string group, string user) {
/*
  Simple wrapper for mod_add to perform LDAP_MOD_ADD user operation only 
         on member attribure of group_dn.
*/
    string user_dn;

    try {
        user_dn = getObjectDN(user);
    }
    catch (ADSearchException) {
        user_dn = user;
    }

    mod_add(group, "member", user_dn);
}

void adclient::groupRemoveUser(string group, string user) {
/*
  Simple wrapper for mod_delete to perform LDAP_MOD_DELETE user operation only 
         on member attribure of group.
*/
    string user_dn;

    try {
        user_dn = getObjectDN(user);
    }
    catch (ADSearchException) {
        user_dn = user;
    }

    mod_delete(group, "member", user_dn);
}

void adclient::mod_add(string object, string attribute, string value) {
/*
  It performs generic LDAP_MOD_ADD operation on dn.
  It adds value to attribute.
  It returns nothing if operation was successfull, throw ADOperationalException - otherwise.
*/
    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    string dn;

    try {
        dn = getObjectDN(object);
    }
    catch (ADSearchException) {
        dn = object;
    }

    LDAPMod *attrs[2];
    LDAPMod attr;
    char *values[2];
    int result;
    string error_msg;

    values[0] = strdup(value.c_str());
    values[1] = NULL;

    attr.mod_op = LDAP_MOD_ADD;
    attr.mod_type = strdup(attribute.c_str());
    attr.mod_values = values;

    attrs[0] = &attr;
    attrs[1] = NULL;

    result = ldap_modify_ext_s(ds, dn.c_str(), attrs, NULL, NULL);
    free(values[0]);
    free(attr.mod_type);
    if (result != LDAP_SUCCESS) {
        error_msg = "Error in mod_add, ldap_modify_ext_s: ";
        error_msg.append(ldap_err2string(result));
        throw ADOperationalException(error_msg, result);
    }
}

void adclient::mod_delete(string object, string attribute, string value) {
/*
  It performs generic LDAP_MOD_DELETE operation on dn.
  It removes value from attribute.
  It returns nothing if operation was successfull, throw ADOperationalException - otherwise.
*/
    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    string dn;

    try {
        dn = getObjectDN(object);
    }
    catch (ADSearchException) {
        dn = object;
    }

    LDAPMod *attrs[2];
    LDAPMod attr;
    char *values[2];
    int result;
    string error_msg;

    values[0] = strdup(value.c_str());
    values[1] = NULL;

    attr.mod_op = LDAP_MOD_DELETE;
    attr.mod_type = strdup(attribute.c_str());
    attr.mod_values = values;

    attrs[0] = &attr;
    attrs[1] = NULL;

    result = ldap_modify_ext_s(ds, dn.c_str(), attrs, NULL, NULL);
    free(values[0]);
    free(attr.mod_type);
    if (result != LDAP_SUCCESS) {
        error_msg = "Error in mod_delete, ldap_modify_ext_s: ";
        error_msg.append(ldap_err2string(result));
        throw ADOperationalException(error_msg, result);
    }
}

void adclient::mod_replace(string object, string attribute, string value) {

    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    string dn;

    try {
        dn = getObjectDN(object);
    }
    catch (ADSearchException) {
        dn = object;
    }

    LDAPMod *attrs[2];
    LDAPMod attr;
    char *values[2];
    int result;
    string error_msg;

    values[0] = strdup(value.c_str());
    values[1] = NULL;

    attr.mod_op = LDAP_MOD_REPLACE;
    attr.mod_type = strdup(attribute.c_str());
    attr.mod_values = values;

    attrs[0] = &attr;
    attrs[1] = NULL;

    result = ldap_modify_ext_s(ds, dn.c_str(), attrs, NULL, NULL);
    if (result != LDAP_SUCCESS) {
        error_msg = "Error in mod_replace, ldap_modify_ext_s: ";
        error_msg.append(ldap_err2string(result));
        throw ADOperationalException(error_msg, result);
    }
    free(values[0]);
    free(attr.mod_type);
}

vector <string> adclient::getUserGroups(string user) {
/*
  It return vector of strings with user groups.
  It returns nothing if operation was successfull, can throw 
     ADBindException, ADSearchException (from called functions).
*/
    vector <string> groups, group_short;
    unsigned int i;
    vector <string> groups_names;

    try {
        groups = getObjectAttribute(user, "memberOf");
    }
    // TODO: Check
    catch (ADSearchException& ex) {
        if (ex.code == AD_ATTRIBUTE_ENTRY_NOT_FOUND) {
            return groups_names;
        }
        throw;
    }

    for (i=0; i<groups.size(); i++) {
        string temp_group = groups[i];
        group_short = getObjectAttribute(temp_group, "sAMAccountName");
        groups_names.push_back(group_short[0]);
    }
    return groups_names;
}

vector <string> adclient::getUsersInGroup(string group) {
/*
  It return vector of strings with members of Active Directory "group".
  It returns nothing if operation was successfull, can throw 
     ADBindException, ADSearchException (from called functions).
*/
    vector <string> users, user_short;
    vector <string> users_names;
    unsigned int i;

    users = getObjectAttribute(group, "member");

    for (i=0; i<users.size(); i++) {
        user_short = getObjectAttribute(users[i], "sAMAccountName");
        users_names.push_back(user_short[0]);
    }
    return users_names;
}

bool adclient::ifDialinUser(string user) {
/*
  It returns true if msNPAllowDialin user attribute set to TRUE, 
             false - otherwise.
  Can throw ADBindException, ADSearchException (from called functions).
*/
    vector <string> user_dn;
    vector <string> dialin;

    try {
        dialin = getObjectAttribute(user, "msNPAllowDialin");
    }
    catch (ADSearchException& ex) {
        if (ex.code == AD_ATTRIBUTE_ENTRY_NOT_FOUND) {
            return false;
        }
        throw;
    }
 
    if (dialin[0] == "TRUE") {
        return true; 
    } else  { return false; }
}

vector <string> adclient::getDialinUsers() {
/*
  It returns vector of strings with all users with msNPAllowDialin = TRUE.
  Can throw ADBindException, ADSearchException (from called functions).
*/
    vector <string> users_dn;
    vector <string> user_short;
    vector <string> dialin_users;
    unsigned int i;
 
    users_dn = searchDN_ext("(msNPAllowDialin=TRUE)");

    for (i=0; i<users_dn.size(); i++) {
        user_short = getObjectAttribute(users_dn[i], "sAMAccountName");
        dialin_users.push_back(user_short[0]);
    }
    return dialin_users;
}

string adclient::getUserDisplayName(string user) {
/*
  It returns string with DisplayName of user.
  Can throw ADSearchException (from called functions).
*/
    vector <string> name = getObjectAttribute(user, "DisplayName");

    return name[0];
}

bool adclient::ifUserDisabled(string user) {
/*
  It returns true if userAccountControl flag of user contain ACCOUNTDISABLE property,
             false - otherwise.
  Can throw ADBindException, ADSearchException (from called functions).
*/
    vector <string> flags;
    int iflags;

    flags = getObjectAttribute(user, "userAccountControl");

    iflags = atoi(flags[0].c_str());

    if (iflags&2) {
        return true;
    } else { return false; }
}

vector <string> adclient::getAllOUs() {
/*
  It returns vector of strings with all organizationalUnit in scope.
  Can throw ADBindException, ADSearchException (from called functions).
*/
    vector <string> ou_dns;
    vector <string> OUs;
    unsigned int i;

    ou_dns = searchDN_ext("(objectclass=organizationalUnit)");

    for (i=0; i<ou_dns.size(); i++) {
        OUs.push_back(ou_dns[i]);
    }
    return OUs;
}

vector <string> adclient::getOUsInOU(string OU) {
/*
  It returns vector of strings with OU's in OU.
  Can throw ADBindException, ADSearchException (from called functions).
*/
    vector <string> ous_dns;
    vector <string> OUs;
    string _search_base;
    unsigned int i;
    int _scope;

    _search_base = search_base;
    search_base = OU;

    _scope = scope;
    scope = LDAP_SCOPE_ONELEVEL;

    ous_dns = searchDN_ext("(objectclass=organizationalUnit)");

    search_base = _search_base;
    scope = _scope;

    for (i=0; i<ous_dns.size(); i++) {
        OUs.push_back(ous_dns[i]);
    }
    return OUs;
}

vector <string> adclient::getUsersInOU(string OU) {
/*
  It returns vector of strings with all users in OU.
  Can throw ADBindException, ADSearchException (from called functions).
*/
    vector <string> users_dn;
    vector <string> user_short;
    string _search_base;
    vector <string> users;
    unsigned int i;
    int _scope;

    _search_base = search_base;
    search_base = OU;

    _scope = scope;
    scope = LDAP_SCOPE_ONELEVEL;
    try {
        users_dn = searchDN_ext("(&(objectClass=user)(objectCategory=person))");
    }
    catch(ADSearchException) {
        /* restore original conditions and then throw exception to upper level */
        search_base = _search_base;
        scope = _scope;
        throw;
    }

    search_base = _search_base;
    scope = _scope;

    for (i=0; i<users_dn.size(); i++) {
        user_short = getObjectAttribute(users_dn[i], "sAMAccountName");
        users.push_back(user_short[0]);
    }

    return users;
}

vector <string> adclient::getUsersInOU_SubTree(string OU) {
/*
  It returns vector of strings with all users in OU and subOUs.
  Can throw ADBindException, ADSearchException (from called functions).
*/
    vector <string> users_dn;
    vector <string> user_short;
    string _search_base;
    vector <string> users;
    unsigned int i;

    _search_base = search_base;
    search_base = OU;

    try {
        users_dn = searchDN_ext("(&(objectClass=user)(objectCategory=person))");
    }
    catch(ADSearchException) {
        /* restore original conditions and then throw exception to upper level */
        search_base = _search_base;
        throw;
    }

    search_base = _search_base;

    for (i=0; i<users_dn.size(); i++) {
        user_short = getObjectAttribute(users_dn[i], "sAMAccountName");
        users.push_back(user_short[0]);
    }

    return users;
}

vector <string> adclient::getGroups() {
/*
  It returns vector of strings with all groups in Active Directory.
  Can throw ADBindException, ADSearchException (from called functions).
*/
    vector <string> groups_dn;
    vector <string> group_short;
    vector <string> groups;
    unsigned int i;

    try {
        groups_dn = searchDN_ext("(objectClass=group)");
    }
    catch(ADSearchException) {
         throw;
    }

    for (i=0; i<groups_dn.size(); i++) {
        group_short = getObjectAttribute(groups_dn[i], "sAMAccountName");
        groups.push_back(group_short[0]);
    }

    return groups;
}

vector <string> adclient::getUsers() {
/*
  It returns vector of strings with all users in Active Directory.
  Can throw ADBindException, ADSearchException (from called functions).
*/
    vector <string> users_dn;
    vector <string> user_short;
    vector <string> users;
    unsigned int i;

    try {
        users_dn = searchDN_ext("(&(objectClass=user)(objectCategory=person))");
    }
    catch(ADSearchException) {
        throw;
    }

    for (i=0; i<users_dn.size(); i++) {
        try {
            user_short = getObjectAttribute(users_dn[i], "sAMAccountName");
        }
        catch (ADSearchException) {
            continue;
        }
        users.push_back(user_short[0]);
    }

    return users;
}

void adclient::CreateOU(string ou) {
    vector <string> ous;
    string sub_ou = "";
    // Split OU to vector
#ifdef LDAP21
    LDAPDN *rez;
#else
    LDAPDN rez;
#endif
    struct berval la_attr;
    struct berval la_value;

    ldap_str2dn(ou.c_str(), &rez, LDAP_DN_FORMAT_LDAPV3);

    for (int i=0; rez[i]!=NULL; ++i) {
#ifdef LDAP21
        la_attr = (****rez[i]).la_attr;
        la_value = (****rez[i]).la_value;
#else
        la_attr = (**rez[i]).la_attr;
        la_value = (**rez[i]).la_value;
#endif
        ous.insert(ous.begin(), string(la_attr.bv_val)+"="+string(la_value.bv_val));
	}
    ldap_memfree(rez);
    string name = ous[ous.size()-1].substr(3);
    // Remove last OU
    ous.pop_back();

    string domain;
    string temp;

    // Separate OU and DC
    for (int i=ous.size()-1; i>=0; --i) {
        temp = ous[i].substr(0,3);
        if (temp == "OU=") {
            sub_ou += ous[i];
            sub_ou += ",";
        }
        else if (temp == "DC=") {
            domain += ous[i];
            domain += ",";
        } else {
            throw ADSearchException("Unknown OU syntax", AD_OU_SYNTAX_ERROR);
        }
    }
    if (sub_ou != "")
       sub_ou.erase(sub_ou.size() - 1, 1);
    domain.erase(domain.size() - 1, 1);

    if ((sub_ou != "")&&(!ifObjectExists(sub_ou+","+domain))) {
       CreateOU(sub_ou+","+domain);
    }

    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    LDAPMod *attrs[3];
    LDAPMod attr1, attr2;

    char *objectClass_values[] = {"organizationalUnit", NULL};

    attr1.mod_op = LDAP_MOD_ADD;
    attr1.mod_type = "objectClass";
    attr1.mod_values = objectClass_values;

    char *name_values[2];
    name_values[0] = strdup(name.c_str());
    name_values[1] = NULL;

    attr2.mod_op = LDAP_MOD_ADD;
    attr2.mod_type = "name";
    attr2.mod_values = name_values;

    attrs[0] = &attr1;
    attrs[1] = &attr2;
    attrs[2] = NULL;

    int result;
    result=ldap_add_ext_s(ds, ou.c_str(), attrs, NULL, NULL);

    free(name_values[0]);

    if(result!=LDAP_SUCCESS) {
        string error_msg = "Error in CreateOU, ldap_add_ext_s: ";
        error_msg.append(ldap_err2string(result));
        throw ADOperationalException(error_msg, result);
    }
}

void adclient::DeleteDN(string dn) {
    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    int result=ldap_delete_ext_s(ds, dn.c_str(), NULL, NULL);

    if (result!=LDAP_SUCCESS) {
        string error_msg = "Error in DeleteDN, ldap_delete_s: ";
        error_msg.append(ldap_err2string(result));
        throw ADOperationalException(error_msg, result);
    }
}

void adclient::CreateUser(string cn, string container, string user_short) {
    LDAPMod *attrs[5];
    LDAPMod attr1, attr2, attr3, attr4;

    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    if (!ifObjectExists(container)) CreateOU(container);

    string dn = "CN=" + cn + "," + container;

    char *objectClass_values[]={"user", NULL};
    char *name_values[2];
    char *accountControl_values[]={"66050", NULL};
    char *upn_values[2];
    string upn;
    string domain;

    attr1.mod_op = LDAP_MOD_ADD;
    attr1.mod_type = "objectClass";
    attr1.mod_values = objectClass_values;

    name_values[0]=strdup(user_short.c_str());
    name_values[1]=NULL;
    attr2.mod_op = LDAP_MOD_ADD;
    attr2.mod_type = "sAMAccountName";
    attr2.mod_values = name_values;

    attr3.mod_op = LDAP_MOD_ADD;
    attr3.mod_type = "userAccountControl";
    attr3.mod_values = accountControl_values;

    domain=dn2domain(dn);
    upn = user_short + "@" + domain;
    upn_values[0]=strdup(upn.c_str());
    upn_values[1]=NULL;
    attr4.mod_op = LDAP_MOD_ADD;
    attr4.mod_type = "userPrincipalName";
    attr4.mod_values = upn_values;

    attrs[0]=&attr1;
    attrs[1]=&attr2;
    attrs[2]=&attr3;
    attrs[3]=&attr4;
    attrs[4]=NULL;

    int result;
    result=ldap_add_ext_s(ds, dn.c_str(), attrs, NULL, NULL);
    free(name_values[0]);
    free(upn_values[0]);
    if(result!=LDAP_SUCCESS) {
        string error_msg = "Error in CreateUser, ldap_add_ext_s: ";
        error_msg.append(ldap_err2string(result));
        throw ADOperationalException(error_msg, result);
    }
}

#if defined OPENLDAP 
string adclient::dn2domain(string dn) {
#ifdef LDAP21
    LDAPDN *exp_dn;
#else
    LDAPDN exp_dn;
#endif
    int i;
    struct berval la_attr;
    struct berval la_value;
    string domain="";

    ldap_str2dn(dn.c_str(), &exp_dn, LDAP_DN_FORMAT_LDAPV3);

    for (i=0; exp_dn[i]!=NULL; ++i) {
#ifdef LDAP21
        la_attr = (****exp_dn[i]).la_attr;
        la_value = (****exp_dn[i]).la_value;
#else
        la_attr = (**exp_dn[i]).la_attr;
        la_value = (**exp_dn[i]).la_value;
#endif
        if (string(la_attr.bv_val) == "DC") {
            domain += la_value.bv_val;
            domain += ".";
        }
    }
    ldap_memfree(exp_dn);
    domain.erase(domain.size()-1, 1);
    return domain;
}
#elif defined SUNLDAP
string adclient::dn2domain(string dn) {
    char** dns;
    char* pcDn = strdup(dn.c_str());
    dns = ldap_explode_dn(pcDn, 0);
    free(pcDn);

    char* next;
    unsigned int i=0;
    string domain = "";
    string temp;

    while ((next = dns[i]) != NULL) {
        if (strncmp(next , "DC=", 3)==0) {
            temp = next;
            temp.erase(0, 3);
            domain += temp;
            domain += ".";
        }
        i++;
    }
    domain.erase(domain.size()-1,1);
    ldap_value_free(dns);
    return domain;
}
#endif

void adclient::UnLockUser(string user) {
    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    vector <string> flags = getObjectAttribute(user, "userAccountControl");

    int iflags = atoi(flags[0].c_str());
    int oldflags = iflags&2;

    if (oldflags) {
        int newflags = iflags^2;
        mod_replace(user, "userAccountControl", itos(newflags));
    }
}

void adclient::setUserDescription(string user, string descr) {
    mod_replace(user, "description", descr);
}

void adclient::setUserPhone(string user, string phone) {
    mod_replace(user, "telephoneNumber", phone);
}

void adclient::setUserDialinAllowed(string user) {
    mod_replace(user, "msNPAllowDialin", "TRUE");
}

void adclient::setUserDialinDisabled(string user) {
    mod_replace(user, "msNPAllowDialin", "FALSE");
}

void adclient::setUserSN(string user, string sn) {
    mod_replace(user, "sn", sn);
}

void adclient::setUserInitials(string user, string initials) {
    mod_replace(user, "initials", initials);
}

void adclient::setUserGivenName(string user, string givenName) {
    mod_replace(user, "givenName", givenName);
}

void adclient::setUserDisplayName(string user, string displayName) {
    mod_replace(user, "displayName", displayName);
}

void adclient::setUserRoomNumber(string user, string roomNum) {
    mod_replace(user, "physicalDeliveryOfficeName", roomNum);
}

void adclient::setUserAddress(string user, string streetAddress) {
    mod_replace(user, "streetAddress", streetAddress);
}

void adclient::setUserInfo(string user, string info) {
    mod_replace(user, "info", info);
}

void adclient::setUserTitle(string user, string title) {
    mod_replace(user, "title", title);
}

void adclient::setUserDepartment(string user, string department) {
    mod_replace(user, "department", department);
}

void adclient::setUserCompany(string user, string company) {
    mod_replace(user, "company", company);
}

void adclient::UnlockUser(string user) {
    mod_replace(user, "lockoutTime", "0");
}

void adclient::setUserPassword(string user, string password) {
    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    string dn;

    try {
        dn = getObjectDN(user);
    }
    catch (ADSearchException) {
        dn = user;
    }

    string quoted_password = "\"" + password + "\"";

    char unicode_password[(MAX_PASSWORD_LENGTH+2)*2];
    memset(unicode_password, 0, sizeof(unicode_password));
    for(unsigned int i=0; i<quoted_password.size(); i++)
        unicode_password[i*2]=quoted_password[i];

    LDAPMod *attrs[2];
    LDAPMod attr1;
    struct berval *bervalues[2];
    struct berval pw;

    pw.bv_val = unicode_password;
    pw.bv_len = quoted_password.size()*2;

    bervalues[0]=&pw;
    bervalues[1]=NULL;

    attr1.mod_type="unicodePwd";
    attr1.mod_op = LDAP_MOD_REPLACE|LDAP_MOD_BVALUES;
    attr1.mod_bvalues = bervalues;

    attrs[0]=&attr1;
    attrs[1]=NULL;

    int result;

    result = ldap_modify_ext_s(ds, dn.c_str(), attrs, NULL, NULL);
    if (result!=LDAP_SUCCESS) {
       string error_msg = "Error in setUserPassord, ldap_add_ext_s: ";
       error_msg.append(ldap_err2string(result));
       throw ADOperationalException(error_msg, result);
    }
}

string adclient::itos(int num) {
    stringstream ss;
    ss << num;
    return(ss.str());
}
