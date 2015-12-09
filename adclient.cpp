#include "stdlib.h"
#include "adclient.h"

/*
  Active Directory class.

  adclient::login can throw ADBindException on errors.
  all search functions can throw ADSearchException on errors.
  all modify functions can throw both ADSearchException and ADOperationalException on errors.
   text description will be in 'msg' property
   numeric code in 'code' property
*/

adclient::adclient() {
/*
  Constructor, to initialize default values of global variables.
*/
    ds = NULL;
    scope = LDAP_SCOPE_SUBTREE;
    nettimeout = -1;
    timelimit  = -1;
    ldap_prefix = "ldap://";
}

adclient::~adclient() {
/*
  Destructor, to automaticaly free initial values allocated at login().
*/
    logout(ds);
}

void adclient::logout(LDAP *ds) {
    if (ds != NULL) {
        ldap_unbind_ext(ds, NULL, NULL);
    }
}

void adclient::login(vector <string> uries, string binddn, string bindpw, string _search_base, bool secured) {
/*
  Wrapper around login to support list of uries
*/
    vector <string>::iterator it;
    for (it = uries.begin(); it != uries.end(); ++it) {
        try {
            login(*it, binddn, bindpw, _search_base, secured);
            return;
        }
        catch (ADBindException&) {
            if (ds != NULL) {
                ldap_unbind_ext(ds, NULL, NULL);
                ds = NULL;
            }

            if (it != (uries.end() - 1)) {
                continue;
            } else {
                throw;
            }
        }
    }
}

void adclient::login(string _uri, string binddn, string bindpw, string _search_base, bool secured) {
/*
  Wrapper around login to fill LDAP* structure
*/
    if (_uri.compare(0, ldap_prefix.size(), ldap_prefix) == 0) {
        login(&ds, _uri, binddn, bindpw, _search_base, secured);
    } else {
        vector<string> servers = get_ldap_servers(_uri);
        login(servers, binddn, bindpw, _search_base, secured);
    }
}

int sasl_interact(LDAP *ds, unsigned flags, void *indefaults, void *in) {
    sasl_defaults *defaults = static_cast<sasl_defaults *>(indefaults);
    sasl_interact_t *interact = static_cast<sasl_interact_t *>(in);
    if (ds == NULL) {
        return LDAP_PARAM_ERROR;
    }

    while(interact->id != SASL_CB_LIST_END) {
        const char *dflt = static_cast<const char *>(interact->defresult);

        switch(interact->id) {
            case SASL_CB_GETREALM:
                dflt = NULL;
                break;
            case SASL_CB_USER:
            case SASL_CB_AUTHNAME:
                dflt = defaults->username.c_str();
                break;
            case SASL_CB_PASS:
                dflt = defaults->password.c_str();
                break;
        }

        interact->result = (dflt && *dflt) ? dflt : static_cast<const char *>("");
        interact->len = strlen(static_cast<const char *>(interact->result));
        interact++;
    }

    return LDAP_SUCCESS;
}

void adclient::login(LDAP **ds, string _uri, string binddn, string bindpw, string _search_base, bool secured) {
/*
  To set various LDAP options and bind to LDAP server.
  It set private pointer to LDAP connection identifier - ds.
  It returns nothing if operation was successfull, throws ADBindException otherwise.
*/
    logout(*ds);

    int result, version, bindresult;

    string error_msg;

    search_base = _search_base;

#if defined OPENLDAP
    result = ldap_initialize(ds, _uri.c_str());
#elif defined SUNLDAP
    result = ldapssl_init(_uri.c_str(), LDAPS_PORT, 1);
#else
#error LDAP library required
#endif
    if (result != LDAP_SUCCESS) {
        error_msg = "Error in ldap_initialize to " + _uri + ": ";
        error_msg.append(ldap_err2string(result));
        throw ADBindException(error_msg, AD_SERVER_CONNECT_FAILURE);
    }

    if (nettimeout != -1) {
        struct timeval optTimeout;
        optTimeout.tv_usec = 0;
        optTimeout.tv_sec = nettimeout;

        result = ldap_set_option(*ds, LDAP_OPT_TIMEOUT, &optTimeout);
        if (result != LDAP_OPT_SUCCESS) {
            error_msg = "Error in ldap_set_option (general timeout): ";
            error_msg.append(ldap_err2string(result));
            throw ADBindException(error_msg, AD_SERVER_CONNECT_FAILURE);
        }

        result = ldap_set_option(*ds, LDAP_OPT_NETWORK_TIMEOUT, &optTimeout);
        if (result != LDAP_OPT_SUCCESS) {
            error_msg = "Error in ldap_set_option (network timeout): ";
            error_msg.append(ldap_err2string(result));
            throw ADBindException(error_msg, AD_SERVER_CONNECT_FAILURE);
        }
    }

    if (timelimit != -1) {
        result = ldap_set_option(*ds, LDAP_OPT_TIMELIMIT, &timelimit);
        if (result != LDAP_OPT_SUCCESS) {
            error_msg = "Error in ldap_set_option (time limit): ";
            error_msg.append(ldap_err2string(result));
            throw ADBindException(error_msg, AD_SERVER_CONNECT_FAILURE);
        }
    }
  
    version = LDAP_VERSION3;
    result = ldap_set_option(*ds, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (result != LDAP_OPT_SUCCESS) {
        error_msg = "Error in ldap_set_option (protocol->v3): ";
        error_msg.append(ldap_err2string(result));
        throw ADBindException(error_msg, AD_SERVER_CONNECT_FAILURE);
    }

    result = ldap_set_option(*ds, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    if (result != LDAP_OPT_SUCCESS) {
        error_msg = "Error in ldap_set_option (referrals->off): ";
        error_msg.append(ldap_err2string(result));
        throw ADBindException(error_msg, AD_SERVER_CONNECT_FAILURE);
    }

    if (secured) {
        string sasl_mech = "DIGEST-MD5";
        unsigned sasl_flags = LDAP_SASL_QUIET;

        sasl_defaults defaults;
        defaults.username = binddn;
        defaults.password = bindpw;

        bindresult = ldap_sasl_interactive_bind_s(*ds, NULL,
                                                  sasl_mech.c_str(),
                                                  NULL, NULL,
                                                  sasl_flags, sasl_interact, &defaults);
    } else {
        struct berval cred;
        struct berval *servcred;

        cred.bv_val = strdup(bindpw.c_str());
        cred.bv_len = bindpw.size();

        bindresult = ldap_sasl_bind_s(*ds, binddn.c_str(), NULL, &cred, NULL, NULL, &servcred);

        memset(cred.bv_val, 0, cred.bv_len);
        free(cred.bv_val);
    }

    if (bindresult != LDAP_SUCCESS) {
        error_msg = "Error while ldap binding to " + _uri + " with " + binddn + " " + bindpw + ": ";
        error_msg.append(ldap_err2string(bindresult));
        throw ADBindException(error_msg, AD_SERVER_CONNECT_FAILURE);
    }

    uri = _uri;
}

bool adclient::checkUserPassword(string user, string password) {
/*
  It returns true of false depends on user credentials correctness.
*/
    LDAP *ld = NULL;

    bool result = true;
    try {
        login(&ld, uri, user, password, search_base, true);
    }
    catch (ADBindException& ex) {
        result = false;
    }
    logout(ld);
    return result;
}

map < string, map < string, vector<string> > > adclient::search(string OU, int scope, string filter, const vector <string> &attributes) {
/*
  General search function.
  It returns map with users found with 'filter' with specified 'attributes'.
*/

    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    int result, errcodep;

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

        int num_results = ldap_count_entries(ds, res);
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

        ldap_msgfree(res);
    } while (morepages);

    for (i = 0; i < attributes.size(); ++i) {
        free(attrs[i]);
    }

    if (cookie != NULL) {
        ber_bvfree(cookie);
    }

    if (error_msg.empty()) {
        return search_result;
    } else {
        ldap_msgfree(res);
        throw ADSearchException(error_msg, result);
    }
}

bool adclient::ifDNExists(string dn) {
/*
  Wrapper around two arguments ifDNExists for searching any objectclass DN
*/
    return ifDNExists(dn, "*");
}

bool adclient::ifDNExists(string dn, string objectclass) {
/*
  It returns true of false depends on object DN existence.
*/
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
/*
  It returns vector with DNs found with 'filter'.
*/
    map < string, map < string, vector<string> > > search_result;

    vector <string> attributes;
    attributes.push_back("1.1");

    search_result = search(search_base.c_str(), scope, filter, attributes);

    vector <string> result;

    map < string, map < string, vector<string> > >::iterator res_it;
    for ( res_it=search_result.begin() ; res_it != search_result.end(); ++res_it ) {
        string dn = (*res_it).first;
        result.push_back(dn);
    }

    return result;
}

string adclient::getObjectDN(string object) {
/*
  It returns user DN by short name.
*/
    if (ifDNExists(object)) {
        return object;
    } else {
        replace(object, "(", "\\(");
        replace(object, ")", "\\)");
        vector <string> dn = searchDN( "(sAMAccountName=" + object + ")" );
        return dn[0];
    }
}

void adclient::mod_add(string object, string attribute, string value) {
/*
  It performs generic LDAP_MOD_ADD operation on object (short_name/DN).
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
  It performs generic LDAP_MOD_DELETE operation on object (short_name/DN).
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
/*
  It performs generic LDAP_MOD_REPLACE operation on object (short_name/DN).
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
/*
  It creates given OU (with subOUs if needed).
  It returns nothing if operation was successfull, throw ADOperationalException - otherwise.
*/
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
/*
  It deletes given DN.
  It returns nothing if operation was successfull, throw ADOperationalException - otherwise.
*/
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
#else
string adclient::dn2domain(string dn) {
    throw ADOperationalException("Don't know how to do dn2domain", 255);
}
#endif

void adclient::CreateUser(string cn, string container, string user_short) {
/*
  It creates user with given common name and short name in given container.
  It will create container if not exists.
  It returns nothing if operation was successfull, throw ADOperationalException - otherwise.
*/
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

void adclient::CreateGroup(string cn, string container, string group_short) {
/*
  It creates new global security group with
    samaccountname=group_short and distinguishedName="CN=cn,container"
  It will create container if not exists.
  It returns nothing if operation was successfull, throw ADOperationalException - otherwise.
 */
    if (ds == NULL) throw ADSearchException("Failed to use LDAP connection handler", AD_LDAP_CONNECTION_ERROR);

    LDAPMod *attrs[4];
    LDAPMod attr1, attr2, attr3;

    if (!ifDNExists(container)) CreateOU(container);

    string dn = "CN=" + cn + "," + container;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wwrite-strings"
    char *objectClass_values[] = {"group", NULL};
    char *name_values[2];
    char *sAMAccountName_values[2];

    //char *accountControl_values[] = {"66050", NULL};
    //char *upn_values[2];
    //string upn;
    //string domain;

    attr1.mod_op = LDAP_MOD_ADD;
    attr1.mod_type = "objectClass";
    attr1.mod_values = objectClass_values;

    name_values[0] = strdup(group_short.c_str());
    name_values[1] = NULL;
    attr2.mod_op = LDAP_MOD_ADD;
    attr2.mod_type = "name";
    attr2.mod_values = name_values;

    sAMAccountName_values[0] = strdup(group_short.c_str());
    sAMAccountName_values[1] = NULL;
    attr3.mod_op = LDAP_MOD_ADD;
    attr3.mod_type = "sAMAccountName";
    attr3.mod_values = sAMAccountName_values;
#pragma GCC diagnostic pop

    attrs[0] = &attr1;
    attrs[1] = &attr2;
    attrs[2] = &attr3;
    attrs[3] = NULL;

    int result;
    result = ldap_add_ext_s(ds, dn.c_str(), attrs, NULL, NULL);
    free(name_values[0]);
    free(sAMAccountName_values[0]);
    if(result != LDAP_SUCCESS) {
        string error_msg = "Error in CreateGroup, ldap_add_ext_s: ";
        error_msg.append(ldap_err2string(result));
        throw ADOperationalException(error_msg, result);
    }
}


void adclient::setUserPassword(string user, string password) {
/*
  It sets user password.
  It returns nothing if operation was successfull, throw ADOperationalException - otherwise.
*/
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
  It returns vector of strings with values for given attribute.
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
/*
  It returns map of all object attributes.
*/
    vector <string> attributes;
    attributes.push_back("*");
    return getObjectAttributes(object, attributes);
}

map <string, vector <string> > adclient::getObjectAttributes(string object, const vector<string> &attributes) {
/*
  It returns map of given object attributes.
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
*/
    vector <string> users_dn;
 
    users_dn = searchDN("(msNPAllowDialin=TRUE)");

    return DNsToShortNames(users_dn);
}

vector <string> adclient::getDisabledUsers() {
/*
  It returns vector of strings with all users with ADS_UF_ACCOUNTDISABLE in userAccountControl.
*/
    vector <string> users_dn;

    users_dn = searchDN("(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=2))");

    return DNsToShortNames(users_dn);
}


string adclient::getUserDisplayName(string user) {
/*
  It returns string with DisplayName of user.
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

/*
Pwd-Last-Set attribute - http://msdn.microsoft.com/en-us/library/windows/desktop/ms679430%28v=vs.85%29.aspx
Account-Expires attribute - http://msdn.microsoft.com/en-us/library/windows/desktop/ms675098%28v=vs.85%29.aspx
ms-DS-User-Account-Control-Computed attribute - http://msdn.microsoft.com/en-us/library/ms677840(v=vs.85).aspx
UserAccountControl - http://support.microsoft.com/kb/305144/en-us
*/
map <string, bool> adclient::getUserControls(string user) {
/*
  It returns boolean map of user controls ('disabled', 'locked', 'dontExpirePassword', 'mustChangePassword', 'expired').
*/
    vector <string> attrs;
    attrs.push_back("userAccountControl");
    attrs.push_back("msDS-User-Account-Control-Computed");
    attrs.push_back("pwdLastSet");
    attrs.push_back("accountExpires");

    map <string, vector <string> > flags;
    flags = getObjectAttributes(user, attrs);

    int iflags1 = atoi(flags["userAccountControl"][0].c_str());
    int iflags2 = atoi(flags["msDS-User-Account-Control-Computed"][0].c_str());
    int iflags3 = atoi(flags["pwdLastSet"][0].c_str());

    long long iflags4 = atoll(flags["accountExpires"][0].c_str());
    time_t expires = FileTimeToPOSIX(iflags4);
    time_t now = time(0);

    map <string, bool> controls;

    controls["disabled"] = (iflags1 & 2);
    controls["locked"] = (iflags2 & 16);

    controls["dontExpirePassword"] = (iflags1 & 65536);
    controls["mustChangePassword"] = ((iflags3 == 0) and (not controls["dontExpirePassword"]));

    controls["expired"] = (now > expires);

    return controls;
}

bool adclient::getUserControl(string user, string control) {
/*
  It returns given user control from adclient::getUserControls.
*/
    map <string, bool> controls;
    controls = getUserControls(user);
    return controls[control];
}

bool adclient::ifUserExpired(string user) {
/*
  It returns 'expired' user control value.
*/
    return getUserControl(user, "expired");
}

bool adclient::ifUserLocked(string user) {
/*
  It returns 'locked' user control value.
*/
    return getUserControl(user, "locked");
}

bool adclient::ifUserDisabled(string user) {
/*
  It returns 'disabled' user control value.
*/
    return getUserControl(user, "disabled");
}

bool adclient::ifUserMustChangePassword(string user) {
/*
  It returns 'mustChangePassword' user control value.
*/
    return getUserControl(user, "mustChangePassword");
}

bool adclient::ifUserDontExpirePassword(string user) {
/*
  It returns 'dontExpirePassword' user control value.
*/
    return getUserControl(user, "dontExpirePassword");
}

vector <string> adclient::getAllOUs() {
/*
  It returns vector of strings with all organizationalUnit in scope.
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
/*
  It enables given user.
*/
    vector <string> flags = getObjectAttribute(user, "userAccountControl");

    int iflags = atoi(flags[0].c_str());
    int oldflags = iflags&2;

    if (oldflags) {
        int newflags = iflags^2;
        mod_replace(user, "userAccountControl", itos(newflags));
    }
}

void adclient::DisableUser(string user) {
/*
  It disables given user.
*/
    vector <string> flags = getObjectAttribute(user, "userAccountControl");

    int iflags = atoi(flags[0].c_str());
    int oldflags = iflags&2;

    if (not oldflags) {
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

void adclient::setUserIpAddress(string user, string ip) {
    try {
        int ipdec = ip2int(ip);
        mod_replace(user, "msRADIUSFramedIPAddress", itos(ipdec));
    } catch (std::invalid_argument ex) {
        throw ADOperationalException(ex.what(), AD_PARAMS_ERROR);
    }
}

void adclient::setObjectAttribute(string object, string attr, string ip) {
    mod_replace(object, attr, ip);
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

    struct berval data;

    for ( char *next = ldap_first_attribute(ds, entry, &berptr);
          next != NULL;
          next = ldap_next_attribute(ds, entry, berptr) ) {

        vector <string> temp;
        struct berval **values = ldap_get_values_len(ds, entry, next);
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

#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
// this magic was copy pasted and adopted from
// https://www.ccnx.org/releases/latest/doc/ccode/html/ccndc-srv_8c_source.html
vector<string> adclient::get_ldap_servers(string domain) {
    union dns_ans {
             HEADER header;
             unsigned char buf[NS_MAXMSG];
          } ans;
    size_t ans_size;

    domain = "_ldap._tcp." + domain;
    char *srv_name = strdup(domain.c_str());
    ans_size = res_search(srv_name, ns_c_in, ns_t_srv, ans.buf, sizeof(ans.buf));

    int qdcount, ancount;
    qdcount = ntohs(ans.header.qdcount);
    ancount = ntohs(ans.header.ancount);

    unsigned char *msg, *msgend;
    msg = ans.buf + sizeof(ans.header);
    msgend = ans.buf + ans_size;

    int size = 0, i;
    for (i = qdcount; i > 0; --i) {
        if ((size = dn_skipname(msg, msgend)) < 0) {
            free(srv_name);
            throw ADBindException("Error while resolving ldap server for " + domain + ": dn_skipname < 0", AD_LDAP_RESOLV_ERROR);
        }
        msg = msg + size + QFIXEDSZ;
    }

    int type = 0, priority = 0, weight = 0, port = 0, recclass = 0, ttl = 0;
    unsigned char *end;
    char host[NS_MAXDNAME];

    vector<string> ret;
    for (i = ancount; i > 0; --i) {
        size = dn_expand(ans.buf, msgend, msg, srv_name, strlen(srv_name)+1);
        if (size < 0) {
            free(srv_name);
            throw ADBindException("Error while resolving ldap server for " + domain + ": dn_expand(srv_name) < 0", AD_LDAP_RESOLV_ERROR);
        }
        msg = msg + size;

        GETSHORT(type, msg);
        GETSHORT(recclass, msg);
        GETLONG(ttl, msg);
        GETSHORT(size, msg);
        if ((end = msg + size) > msgend) {
            free(srv_name);
            throw ADBindException("Error while resolving ldap server for " + domain + ": (msg + size) > msgend", AD_LDAP_RESOLV_ERROR);
        }

        if (type != ns_t_srv) {
            msg = end;
            continue;
        }

        GETSHORT(priority, msg);
        GETSHORT(weight, msg);
        GETSHORT(port, msg);
        size = dn_expand(ans.buf, msgend, msg, host, sizeof(host));
        if (size < 0) {
            free(srv_name);
            throw ADBindException("Error while resolving ldap server for " + domain + ": dn_expand(host) < 0", AD_LDAP_RESOLV_ERROR);
        }
        //std::cout << priority << " " << weight << " " << ttl << " " << host << ":" << port << std::endl;
        ret.push_back(string("ldap://") + string(host));
        msg = end;
    }
    free(srv_name);
    return ret;
}
#pragma GCC diagnostic pop
