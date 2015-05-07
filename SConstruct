#!/usr/bin/env python
import sys
Help("""
Type: 'scons' to build libadclient library
      'scons install [prefix=/path]' to install libadclient library and header file [to /path/{include,lib}]
      'scons -c install [prefix=/path]' to uninstall libadclient library and header file [from /path/{include,lib}]
""")

ldap_test_source_file = """
#include <ldap.h>
int main() {
    LDAPDN exp_dn;
    ldap_str2dn("test", &exp_dn, LDAP_DN_FORMAT_LDAPV3);
    return 0;
}
"""

openldap_test_source_file = """
#include <ldap.h>
#include <string.h>
int main() {
    return strcmp( LDAP_VENDOR_NAME,"OpenLDAP");
}
"""

sunldap_test_source_file = """
#include <ldap.h>
#include <string.h>
int main() {
    return strcmp( LDAP_VENDOR_NAME,"Sun Microsystems Inc.");
}
"""

LibPath = ['/usr/lib', '/usr/local/lib']
IncludePath = ['.', '/usr/local/include', '/usr/include']

env = Environment(CCFLAGS = " -O0 -g -Wall ", LIBPATH = LibPath, CPPPATH = IncludePath)

PREFIX=ARGUMENTS.get('prefix', '/usr/local')

IGNORE = False
ignore = ['--help', '-h', '-c']
for arg in ignore:
    if arg in sys.argv:
       IGNORE = True
       break

def checkLdapVersion(context):
   context.Message('Checking for new LDAPDN definition... ')
   result = context.TryLink(ldap_test_source_file, ".cpp")
   context.Result(result)
   return result

def checkOpenLdap(context):
   context.Message('Checking for OPENLDAP definition... ')
   result = context.TryRun(openldap_test_source_file, ".cpp")
   context.Result(result[0])
   return result[0]

def checkSundap(context):
   context.Message('Checking for SunLDAP definition... ')
   result = context.TryRun(sunldap_test_source_file, ".cpp")
   context.Result(result[0])
   return result[0]


if not IGNORE:
   conf = Configure(env, custom_tests = {'checkLdapVersion' : checkLdapVersion, 'openldap' : checkOpenLdap, 'sunldap':checkSundap})
   check_c_funcs = ['strdup' , 'strlen', 'strcmp', 'memset', 'bzero']
   for func in check_c_funcs:
       if not conf.CheckFunc(func):
          print "Failed."
          Exit(1)

   check_c_headers = ['ldap.h', 'sasl/sasl.h']
   for file in check_c_headers:
       if not conf.CheckCHeader(file):
          print "Failed."
          Exit(1)

   check_cxx_headers = ['string', 'vector']
   for file in check_cxx_headers:
       if not conf.CheckCXXHeader(file):
          print "Failed."
          Exit(1)

   env.Append(LIBS=["ldap", "sasl2", "stdc++"])
   check_libs = ['ldap', 'sasl2', 'stdc++']
   for lib in check_libs:
       if not conf.CheckLib(lib):
          print "Failed."
          Exit(1)
   if conf.openldap():
      env.Append(CCFLAGS=" -DOPENLDAP ")
   elif conf.sunldap():
      env.Append(CCFLAGS=" -DSUNLDAP ")
   if not conf.checkLdapVersion():
      env.Append(CCFLAGS=" -DLDAP21 ")
   env = conf.Finish()

libadclient_target = env.SharedLibrary('adclient', ['adclient.cpp'])

lib_install_target = env.Install(PREFIX+'/lib', libadclient_target)
header_install_target = env.Install(PREFIX+'/include', 'adclient.h')

env.Alias('install', lib_install_target)
env.Alias('install', header_install_target)
