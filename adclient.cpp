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

map < string, map < string, vector<string> > > adclient::search(string OU, int scope, string filter, const vector <string> &attributes) {
    int result, errcodep, num_results;

    char *attrs[50];
    int attrsonly = 0;

    string error_msg = "";

    ber_int_t       pagesize = 1000;
    ber_int_t       totalcount;
    struct berval   *cookie = NULL;
    int             iscritical = 1;

    LDAPControl     *serverctrls[2] = { NULL, NULL };
    LDAPControl     *pagecontrol = NULL;
    LDAPControl     **returnedctrls = NULL;

    LDAPMessage *res = NULL;
    LDAPMessage *entry;

    char *dn;

    bool morepages;

    map < string, map < string, vector<string> > > search_result;

    if (attributes.size() > 50) throw ADSearchException("Cant return more than 50 attributes", AD_PARAMS_ERROR);

    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    unsigned int i;
    for (i = 0; i < attributes.size(); ++i) {
        attrs[i] = strdup(attributes[i].c_str());
    }
    attrs[i] = NULL;

    do {
        result = ldap_create_page_control(ds, pagesize, cookie, iscritical, &pagecontrol);
        if (result != LDAP_SUCCESS) {
            error_msg = "Failed to create page control: ";
            error_msg.append(ldap_err2string(result));
            break;
        }
        serverctrls[0] = pagecontrol;

        /* Search for entries in the directory using the parmeters.       */
        result = ldap_search_ext_s(ds, OU.c_str(), scope, filter.c_str(), attrs, attrsonly, serverctrls, NULL, NULL, LDAP_NO_LIMIT, &res);
        if ((result != LDAP_SUCCESS) & (result != LDAP_PARTIAL_RESULTS)) {
            error_msg = "Error in paged ldap_search_ext_s: ";
            error_msg.append(ldap_err2string(result));
            break;
        }
        serverctrls[0] = NULL;
        ldap_control_free(pagecontrol);
        pagecontrol = NULL;

        num_results = ldap_count_entries(ds, res);
        if (num_results == 0) {
            error_msg = filter + " not found";
            result = AD_OBJECT_NOT_FOUND;
            break;
        }

        map < string, vector<string> > valuesmap;

        for ( entry = ldap_first_entry(ds, res);
              entry != NULL;
              entry = ldap_next_entry(ds, entry) ) {
            dn = ldap_get_dn(ds, entry);
            valuesmap = _getvalues(entry);
            search_result[dn] = valuesmap;
            ldap_memfree(dn);
        }

        /* Parse the results to retrieve the contols being returned.      */
        result = ldap_parse_result(ds, res, &errcodep, NULL, NULL, NULL, &returnedctrls, false);
        if (result != LDAP_SUCCESS) {
            error_msg = "Failed to parse result: ";
            error_msg.append(ldap_err2string(result));
            break;
        }

        /* Parse the page control returned to get the cookie and          */
        /* determine whether there are more pages.                        */
        pagecontrol = ldap_control_find( LDAP_CONTROL_PAGEDRESULTS, returnedctrls, NULL );
        if (pagecontrol == NULL) {
            error_msg = "Failed to find PAGEDRESULTS control";
            result = 255;
            break;
        }

        struct berval newcookie;
        result = ldap_parse_pageresponse_control( ds, pagecontrol, &totalcount, &newcookie );
        if (result != LDAP_SUCCESS) {
            error_msg = "Failed to parse pageresponse control: ";
            error_msg.append(ldap_err2string(result));
            break;
        }
        ber_bvfree(cookie);
        cookie = (berval*) ber_memalloc( sizeof( struct berval ) );
        if (cookie == NULL) {
            error_msg = "Failed to allocate memory for cookie";
            result = 255;
            break;
        }
        *cookie = newcookie;

        /* Cleanup the controls used. */
        ldap_controls_free(returnedctrls);
        returnedctrls = NULL;

        /* Determine if the cookie is not empty, indicating there are more pages for these search parameters. */
        if (cookie && cookie->bv_val != NULL && (strlen(cookie->bv_val) > 0)) {
            morepages = true;
        } else {
            morepages = false;
        }

    } while (morepages);

    ldap_msgfree(res);

    if (error_msg.empty()) {
        return search_result;
    } else {
        throw ADSearchException(error_msg, result);
    }
}

bool adclient::ifDNExists(string dn) {
    return ifDNExists(dn, "*");
}

bool adclient::ifDNExists(string dn, string objectclass) {
    int result;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wwrite-strings"
    char *attrs[] = {"1.1", NULL};
#pragma GCC diagnostic pop
    LDAPMessage *res;
    string error_msg;
    int attrsonly = 1;

    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    string filter = "(objectclass=" + objectclass + ")";
    result = ldap_search_ext_s(ds, dn.c_str(), scope, filter.c_str(), attrs, attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
    ldap_msgfree(res);

    return (result == LDAP_SUCCESS);
}

vector <string> adclient::searchDN(string filter) {
    map < string, map < string, vector<string> > > search_result;

    vector <string> attributes;
    attributes.push_back("1.1");

    search_result = search(search_base.c_str(), scope, filter, attributes);

    vector <string> result;

    map < string, map < string, vector<string> > >::iterator res_it;
    for ( res_it=search_result.begin() ; res_it != search_result.end(); res_it++ ) {
        string dn = (*res_it).first;
        result.push_back(dn);
    }

    return result;
}

string adclient::getObjectDN(string object) {
/*
  It returns string with DN of object_short.
  Can throw ADSearchException (from called functions).
*/
    if (ifDNExists(object)) {
        return object;
    } else {
        vector <string> dn = searchDN( "(sAMAccountName=" + object + ")" );
        return dn[0];
    }
}

void adclient::mod_add(string object, string attribute, string value) {
/*
  It performs generic LDAP_MOD_ADD operation on dn.
  It adds value to attribute.
  It returns nothing if operation was successfull, throw ADOperationalException - otherwise.
*/
    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    string dn = getObjectDN(object);

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

    string dn = getObjectDN(object);

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

    string dn = getObjectDN(object);

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

    if ((sub_ou != "")&&(!ifDNExists(sub_ou+","+domain))) {
       CreateOU(sub_ou+","+domain);
    }

    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    LDAPMod *attrs[3];
    LDAPMod attr1, attr2;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wwrite-strings"
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
#pragma GCC diagnostic pop

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

void adclient::CreateUser(string cn, string container, string user_short) {
    LDAPMod *attrs[5];
    LDAPMod attr1, attr2, attr3, attr4;

    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    if (!ifDNExists(container)) CreateOU(container);

    string dn = "CN=" + cn + "," + container;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wwrite-strings"
    char *objectClass_values[] = {"user", NULL};
    char *name_values[2];
    char *accountControl_values[] = {"66050", NULL};
    char *upn_values[2];
    string upn;
    string domain;

    attr1.mod_op = LDAP_MOD_ADD;
    attr1.mod_type = "objectClass";
    attr1.mod_values = objectClass_values;

    name_values[0] = strdup(user_short.c_str());
    name_values[1] = NULL;
    attr2.mod_op = LDAP_MOD_ADD;
    attr2.mod_type = "sAMAccountName";
    attr2.mod_values = name_values;

    attr3.mod_op = LDAP_MOD_ADD;
    attr3.mod_type = "userAccountControl";
    attr3.mod_values = accountControl_values;

    domain=dn2domain(dn);
    upn = user_short + "@" + domain;
    upn_values[0] = strdup(upn.c_str());
    upn_values[1] = NULL;
    attr4.mod_op = LDAP_MOD_ADD;
    attr4.mod_type = "userPrincipalName";
    attr4.mod_values = upn_values;
#pragma GCC diagnostic pop

    attrs[0] = &attr1;
    attrs[1] = &attr2;
    attrs[2] = &attr3;
    attrs[3] = &attr4;
    attrs[4] = NULL;

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

void adclient::setUserPassword(string user, string password) {
    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    string dn = getObjectDN(user);

    string quoted_password = "\"" + password + "\"";

    char unicode_password[(MAX_PASSWORD_LENGTH+2)*2];
    memset(unicode_password, 0, sizeof(unicode_password));
    for (unsigned int i = 0; i < quoted_password.size(); ++i) {
        unicode_password[i*2] = quoted_password[i];
    }

    LDAPMod *attrs[2];
    LDAPMod attr1;
    struct berval *bervalues[2];
    struct berval pw;

    pw.bv_val = unicode_password;
    pw.bv_len = quoted_password.size()*2;

    bervalues[0] = &pw;
    bervalues[1] = NULL;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wwrite-strings"
    attr1.mod_type="unicodePwd";
#pragma GCC diagnostic pop
    attr1.mod_op = LDAP_MOD_REPLACE|LDAP_MOD_BVALUES;
    attr1.mod_bvalues = bervalues;

    attrs[0] = &attr1;
    attrs[1] = NULL;

    int result;

    result = ldap_modify_ext_s(ds, dn.c_str(), attrs, NULL, NULL);
    if (result!=LDAP_SUCCESS) {
       string error_msg = "Error in setUserPassord, ldap_add_ext_s: ";
       error_msg.append(ldap_err2string(result));
       throw ADOperationalException(error_msg, result);
    }
}

vector <string> adclient::getObjectAttribute(string object, string attribute) {
/*
  It returns vector of strings with one entry for each attribute/value pair,
  throws ADSearchException if no values were found, or if error occupied.
*/
    vector <string> attributes;
    attributes.push_back(attribute);

    map < string, vector<string> > attrs;
    attrs = getObjectAttributes(object, attributes);

    try {
        return attrs.at(attribute);
    }
    catch (const std::out_of_range&) {
        throw ADSearchException("No such attribute '" + attribute + "' in '" + object + "'", AD_ATTRIBUTE_ENTRY_NOT_FOUND);
    }
}

map <string, vector <string> > adclient::getObjectAttributes(string object) {
    vector <string> attributes;
    attributes.push_back("*");
    return getObjectAttributes(object, attributes);
}

map <string, vector <string> > adclient::getObjectAttributes(string object, const vector<string> &attributes) {
/*
  It returns map of attributes with vector of values, with all object attributes
  throws ADSearchException if no values were found, or if error occupied.
*/
    string dn = getObjectDN(object);

    map < string, map < string, vector<string> > > search_result;

    search_result = search(dn, LDAP_SCOPE_BASE, "(objectclass=*)", attributes);

    map < string, vector<string> > attrs;
    try {
        attrs = search_result.at(dn);
    }
    catch (const std::out_of_range&) {
        attrs = map < string,vector<string> >();
    }

    return attrs;
}

void adclient::groupAddUser(string group, string user) {
/*
  Simple wrapper for mod_add to perform LDAP_MOD_ADD user operation only
         on member attribure of group_dn.
*/
    string dn = getObjectDN(user);

    mod_add(group, "member", dn);
}

void adclient::groupRemoveUser(string group, string user) {
/*
  Simple wrapper for mod_delete to perform LDAP_MOD_DELETE user operation only
         on member attribure of group.
*/
    string dn = getObjectDN(user);

    mod_delete(group, "member", dn);
}


vector <string> adclient::getUserGroups(string user) {
/*
  It return vector of strings with user groups.
  It returns nothing if operation was successfull, can throw
     ADBindException, ADSearchException (from called functions).
*/
    vector <string> groups;

    try {
        groups = getObjectAttribute(user, "memberOf");
    }
    catch (ADSearchException& ex) {
        if (ex.code == AD_ATTRIBUTE_ENTRY_NOT_FOUND) {
            return vector<string>();
        }
        throw;
    }

    return DNsToShortNames(groups);
}

vector <string> adclient::getUsersInGroup(string group) {
/*
  It return vector of strings with members of Active Directory "group".
  It returns nothing if operation was successfull, can throw
     ADBindException, ADSearchException (from called functions).
*/
    vector <string> users;

    try {
        users = getObjectAttribute(group, "member");
    }
    catch (ADSearchException& ex) {
        if (ex.code == AD_ATTRIBUTE_ENTRY_NOT_FOUND) {
            return vector <string>();
        }
        throw;
    }

    return DNsToShortNames(users);
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
 
    users_dn = searchDN("(msNPAllowDialin=TRUE)");

    return DNsToShortNames(users_dn);
}

string adclient::getUserDisplayName(string user) {
/*
  It returns string with DisplayName of user.
  Can throw ADSearchException (from called functions).
*/
    vector <string> name;
    try {
        name = getObjectAttribute(user, "displayName");
    }
    catch (ADSearchException& ex) {
        if (ex.code == AD_ATTRIBUTE_ENTRY_NOT_FOUND) {
            return "";
        }
        throw;
    }
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

    ou_dns = searchDN("(objectclass=organizationalUnit)");

    for (unsigned int i = 0; i < ou_dns.size(); ++i) {
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
    int _scope;

    _search_base = search_base;
    search_base = OU;

    _scope = scope;
    scope = LDAP_SCOPE_ONELEVEL;

    ous_dns = searchDN("(objectclass=organizationalUnit)");

    search_base = _search_base;
    scope = _scope;

    for (unsigned int i = 0; i < ous_dns.size(); ++i) {
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
    string _search_base;
    int _scope;

    _search_base = search_base;
    search_base = OU;

    _scope = scope;
    scope = LDAP_SCOPE_ONELEVEL;
    try {
        users_dn = searchDN("(&(objectClass=user)(objectCategory=person))");
    }
    catch(ADSearchException) {
        /* restore original conditions and then throw exception to upper level */
        search_base = _search_base;
        scope = _scope;
        throw;
    }

    search_base = _search_base;
    scope = _scope;

    return DNsToShortNames(users_dn);
}

// TODO: check if it is works
vector <string> adclient::getUsersInOU_SubTree(string OU) {
/*
  It returns vector of strings with all users in OU and subOUs.
  Can throw ADBindException, ADSearchException (from called functions).
*/
    vector <string> users_dn;
    string _search_base;

    _search_base = search_base;
    search_base = OU;

    try {
        users_dn = searchDN("(&(objectClass=user)(objectCategory=person))");
    }
    catch(ADSearchException) {
        /* restore original conditions and then throw exception to upper level */
        search_base = _search_base;
        throw;
    }

    search_base = _search_base;

    return DNsToShortNames(users_dn);
}

vector <string> adclient::getGroups() {
/*
  It returns vector of strings with all groups in Active Directory.
  Can throw ADBindException, ADSearchException (from called functions).
*/
    vector <string> groups_dn;

    try {
        groups_dn = searchDN("(objectClass=group)");
    }
    catch(ADSearchException) {
         throw;
    }

    return DNsToShortNames(groups_dn);
}

vector <string> adclient::getUsers() {
/*
  It returns vector of strings with all users in Active Directory.
  Can throw ADBindException, ADSearchException (from called functions).
*/
    vector <string> users_dn;

    try {
        users_dn = searchDN("(&(objectClass=user)(objectCategory=person))");
    }
    catch(ADSearchException) {
        throw;
    }

    return DNsToShortNames(users_dn);
}

void adclient::EnableUser(string user) {
    vector <string> flags = getObjectAttribute(user, "userAccountControl");

    int iflags = atoi(flags[0].c_str());
    int oldflags = iflags&2;

    if (oldflags) {
        int newflags = iflags^2;
        mod_replace(user, "userAccountControl", itos(newflags));
    }
}

void adclient::UnLockUser(string user) {
    mod_replace(user, "lockoutTime", "0");
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

/*
AD can set following limit (http://support.microsoft.com/kb/315071/en-us):
 MaxValRange - This value controls the number of values that are returned
   for an attribute of an object, independent of how many attributes that
   object has, or of how many objects were in the search result. If an
   attribute has more than the number of values that are specified by the
   MaxValRange value, you must use value range controls in LDAP to retrieve
   values that exceed the MaxValRange value. MaxValueRange controls the
   number of values that are returned on a single attribute on a single object.

OpenLDAP does not support ranged controls for values:
  https://www.mail-archive.com/openldap-its@openldap.org/msg00962.html

So the only way is it increase MaxValRange in DC:
 Ntdsutil.exe
   LDAP policies
     connections
       connect to server "DNS name of server"
       q
     Show Values
     Set MaxValRange to 10000
     Show Values
     Commit Changes
     Show Values
     q
   q
*/
map < string, vector<string> > adclient::_getvalues(LDAPMessage *entry) {
    if ((ds == NULL) || (entry == NULL)) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    map < string, vector<string> > result;

    BerElement *berptr;

    struct berval **values;
    struct berval data;

    for ( char *next = ldap_first_attribute(ds, entry, &berptr);
          next != NULL;
          next = ldap_next_attribute(ds, entry, berptr) ) {

        vector <string> temp;
        values = ldap_get_values_len(ds, entry, next);
        if (values == NULL) {
            string error = "Error in ldap_get_values_len for _getvalues: no values found";
            throw ADSearchException(error, AD_ATTRIBUTE_ENTRY_NOT_FOUND);
        }
        for (unsigned int i = 0; values[i] != NULL; ++i) {
            data = *values[i];
            temp.push_back(data.bv_val);
        }
        result[next] = temp;
        //cout << "_getvalues['" << next << "'] = '" << vector2string(temp) << "'" << endl;
        ldap_memfree(next);
        ldap_value_free_len(values);
    }

    ber_free(berptr, 0);

    return result;
}

vector <string> adclient::DNsToShortNames(vector <string> &v) {
    vector <string> result;

    vector <string>::iterator it;
    for (it = v.begin(); it != v.end(); ++it) {
        vector <string> short_v;
        try {
            short_v = getObjectAttribute(*it, "sAMAccountName");
        }
        catch (ADSearchException& ex) {
            if (ex.code == AD_ATTRIBUTE_ENTRY_NOT_FOUND) {
                result.push_back(*it);
                continue;
            }
            throw;
        }
        result.push_back(short_v[0]);
    }
    return result;
}

string adclient::itos(int num) {
    std::stringstream ss;
    ss << num;
    return(ss.str());
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

    string dn = getObjectDN(object);

    attrs[0] = strdup(attribute.c_str());
    attrs[1] = NULL;
    result = ldap_search_ext_s(ds, dn.c_str(), LDAP_SCOPE_BASE, "(objectclass=*)", attrs, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
    free(attrs[0]);
    if (result != LDAP_SUCCESS) {
        if (res != NULL) ldap_msgfree(res);
        error_msg = "Error in ldap_search_ext_s for getBinaryObjectAttribute: ";
        error_msg.append(ldap_err2string(result));
        throw ADSearchException(error_msg, result);
    }
    num_entries=ldap_count_entries(ds, res);
    if (num_entries == 0) {
        error_msg = "No entries found in getBinaryObjectAttribute for user " + dn;
        ldap_msgfree(res);
        throw ADSearchException(error_msg, AD_OBJECT_NOT_FOUND);
    } else if (num_entries > 1) {
        error_msg = "More than one entry found in getBinaryObjectAttribute for user " + dn;
        ldap_msgfree(res);
        throw ADSearchException(error_msg, AD_OBJECT_NOT_FOUND);
    }

    entry=ldap_first_entry(ds, res);
    struct berval **_values;
    _values=ldap_get_values_len(ds, entry, attribute.c_str());
    if (_values == NULL) {
       error_msg = "Error in ldap_get_values_len for getBinaryObjectAttribute: no values found for attribute " + attribute + " in object " + dn;
        ldap_msgfree(res);
        throw ADSearchException(error_msg, AD_ATTRIBUTE_ENTRY_NOT_FOUND);
    }
    for (unsigned int i = 0; _values[i] != NULL; ++i) {
        value = *_values[i];
    }
    ldap_value_free_len(_values);
    ldap_msgfree(res);

    return value;
}
