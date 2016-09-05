#include <ldap.h>
#include <sasl/sasl.h>
#include <string>
#include <cstdlib>
#include <iostream>

using std::string;
using std::cout;
using std::endl;

struct sasl_defaults_digest_md5 {
    string username;
    string password;
};

int sasl_interact_digest_md5(LDAP *ds, unsigned flags, void *indefaults, void *in) {
    sasl_defaults_digest_md5 *defaults = static_cast<sasl_defaults_digest_md5 *>(indefaults);
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

int sasl_bind_digest_md5(LDAP *ds, string binddn, string bindpw) {
    int bindresult;

    string sasl_mech = "DIGEST-MD5";
    unsigned sasl_flags = LDAP_SASL_QUIET;

    sasl_defaults_digest_md5 defaults;
    defaults.username = binddn;
    defaults.password = bindpw;

    bindresult = ldap_sasl_interactive_bind_s(ds, NULL,
                                              sasl_mech.c_str(),
                                              NULL, NULL,
                                              sasl_flags, sasl_interact_digest_md5, &defaults);
    return bindresult;
}

int sasl_bind_simple(LDAP *ds, string binddn, string bindpw) {
    int bindresult;

    struct berval cred;
    struct berval *servcred;

    cred.bv_val = strdup(bindpw.c_str());
    cred.bv_len = bindpw.size();

    bindresult = ldap_sasl_bind_s(ds, binddn.c_str(), NULL, &cred, NULL, NULL, &servcred);

    memset(cred.bv_val, 0, cred.bv_len);
    free(cred.bv_val);

    return bindresult;
}
