import _adclient
from _adclient import *

class ADClient:
      """
         Active Directory manipulation class wrapper for low level c++ class.
      """
      AD_SCOPE_BASE = 0
      AD_SCOPE_ONELEVEL = 1
      AD_SCOPE_SUBTREE = 2

      def __init__(self):
          """ Returns a copy of adclient object.
          """
          self.obj = _adclient.new_adclient()

      def login(self, uri, binddn, bindpw, search_base):
          """ ADClient login function.
                It binds to Active Directory uri (e.g. "ldap://example.org") 
                   as binddn (e.g. "administrator@example.org") identified by 
                   bindpw (e.g. "password"). Search Base for every ldap search 
                   would be search_base (e.g. "dc=example,dc=org").
                   It returns nothing if operation was successfull, 
                      throws ADBindError - otherwise.
          """
          _adclient.login_adclient(self.obj, uri, binddn, bindpw, search_base)

      def searchDN(self, filter):
          """ ADClient searchDN function.
          """
          return _adclient.searchDN_adclient(self.obj, filter)

      def search(self, ou, scope, filter, attributes):
          """ ADClient search function.
          """
          return _adclient.search_adclient(self.obj, ou, scope, filter, attributes)

      def getUserGroups(self, user):
          """ ADClient getUserGroups function.
                It returns list with "user" groups if operation was successfull,
                   throws ADBindError, ADSearchError  - otherwise.
          """
          return _adclient.getUserGroups_adclient(self.obj, user)

      def getUsersInGroup(self, group):
          """ ADClient getUsersInGroup function.
                It returns list with members of Active Directory "group" if operation was successfull,
                   throws ADBindError, ADSearchError  - otherwise.
          """
          return _adclient.getUsersInGroup_adclient(self.obj, group)

      def groupAddUser(self, group, user):
          """ ADClient groupAddUser function.
                It adds "user" to Active Directory "group".
                It returns nothing if operation was successfull, 
                   throws ADBindError, ADSearchError, ADOperationalError - otherwise.
          """
          _adclient.groupAddUser_adclient(self.obj, group, user)

      def groupRemoveUser(self, group, user):
          """ ADClient groupRemoveUser function.
                It removes "user" from Active Directory "group".
                It returns nothing if operation was successfull, 
                   throws ADBindError, ADSearchError, ADOperationalError - otherwise.
          """
          _adclient.groupRemoveUser_adclient(self.obj, group, user)

      def ifDialinUser(self, user):
          """ ADClient ifDialinUser function.
                It returns True if msNPAllowDialin user attribute set to TRUE, False - otherwise.
                   Can throws ADBindError, ADSearchError on errors.
          """
          if (_adclient.ifDialinUser_adclient(self.obj, user) == 1):
             return True
          else:
             return False

      def getDialinUsers(self):
          """ ADClient getDialinUsers function.
                It returns list of all users with msNPAllowDialin = TRUE.
                   Can throws ADBindError, ADSearchError on errors.
          """
          return _adclient.getDialinUsers_adclient(self.obj)

      def getObjectDN(self, user):
          """ ADClient getObjectDN function.
                It returns user DN by short name.
                   Can throws ADBindError, ADSearchError on errors.
          """
          return _adclient.getObjectDN_adclient(self.obj, user)

      def ifUserDisabled(self, user):
          """ ADClient ifUserDisabled function.
                It returns True if UserAccountControl flag contain ACCOUNTDISABLE property, 
                   False - otherwise.
                   Can throws ADBindError, ADSearchError on errors.
          """
          if (_adclient.ifUserDisabled_adclient(self.obj, user) == 1):
             return True
          else:
             return False

      def ifDNExists(self, dn, objectclass = '*'):
          if (_adclient.ifDNExists_adclient(self.obj, dn, objectclass) == 1):
             return True
          else:
             return False

      def getAllOUs(self):
          """ ADClient getAllOUs function.
                It returns list of all organizationalUnits in search_base.
                   Can throws ADBindError, ADSearchError on errors.
          """
          return _adclient.getAllOUs_adclient(self.obj)

      def getUsersInOU(self, OU):
          """ ADClient getUsersInOU function.
                It returns list of all users in OU.
                   Can throws ADBindError, ADSearchError on errors.
          """
          return _adclient.getUsersInOU_adclient(self.obj, OU)

      def getUsersInOU_SubTree(self, OU):
          """ ADClient getUsersInOU function.
                It returns list of all users in OU.
                   Can throws ADBindError, ADSearchError on errors.
          """
          return _adclient.getUsersInOU_SubTree_adclient(self.obj, OU)

      def getGroups(self):
          """ ADClient getUsersInOU function.
                It returns list of all users in OU.
                   Can throws ADBindError, ADSearchError on errors.
          """
          return _adclient.getGroups_adclient(self.obj)

      def getUsers(self):
          """ ADClient getUsers function.
                It returns list of all users in AD.
                   Can throws ADBindError, ADSearchError on errors.
          """
          return _adclient.getUsers_adclient(self.obj)

      def getOUsInOU(self, OU):
          """ ADClient getOUsInOU function.
                It returns list of all OUs in OU.
                   Can throws ADBindError, ADSearchError on errors.
          """
          return _adclient.getOUsInOU_adclient(self.obj, OU)

      def getUserDisplayName(self, user):
          """ ADClient getUserDisplayName function.
                It returns string with user DisplayName property.
                   Can throws ADBindError, ADSearchError on errors.
          """
          return _adclient.getUserDisplayName_adclient(self.obj, user)

      def getObjectAttribute(self, object, attribute):
          """ ADClient getObjectAttribute function.
                It returns string with attribute of object.
                   Can throws ADBindError, ADSearchError on errors.
          """
          return _adclient.getObjectAttribute_adclient(self.obj, object, attribute)

      def getObjectAttributes(self, object):
          """ ADClient getObjectAttributes function.
                It returns list of tuples (attribute, list_of_values) with all object attributes.
                   Can throws ADBindError, ADSearchError on errors.
          """
          return _adclient.getObjectAttributes_adclient(self.obj, object)

      def CreateUser(self, cn, container, short_name):
          _adclient.CreateUser_adclient(self.obj, cn, container, short_name)

      def DeleteDN(self, dn):
          _adclient.DeleteDN_adclient(self.obj, dn)

      def CreateOU(self, ou):
          _adclient.CreateOU_adclient(self.obj, ou)

      def UnLockUser(self, short_name):
          _adclient.UnLockUser_adclient(self.obj, short_name)

      def setUserDescription(self, dn, descr):
          _adclient.setUserDescription_adclient(self.obj, dn, descr)

      def setUserPassword(self, dn, password):
          _adclient.setUserPassword_adclient(self.obj, dn, password)

      def setUserDialinAllowed(self, user):
          _adclient.setUserDialinAllowed_adclient(self.obj, user)

      def setUserDialinDisabled(self, user):
          _adclient.setUserDialinDisabled_adclient(self.obj, user)

      def setUserSN_adclient(self, user, sn):
          _adclient.setUserSN_adclient(self.obj, user, sn)

      def setUserInitials(self, user, initials):
          _adclient.setUserInitials_adclient(self.obj, user, initials)

      def setUserGivenName(self, user, givenName):
          _adclient.setUserGivenName_adclient(self.obj, user, givenName)

      def setUserDisplayName(self, user, displayName):
          _adclient.setUserDisplayName_adclient(self.obj, user, displayName)

      def setUserRoomNumber(self, user, roomNum):
          _adclient.setUserRoomNumber_adclient(self.obj, user, roomNum)

      def setUserAddress(self, user, streetAddress):
          _adclient.setUserAddress_adclient(self.obj, user, streetAddress)

      def setUserInfo(self, user, info):
          _adclient.setUserInfo_adclient(self.obj, user, info)

      def setUserTitle(self, user, title):
          _adclient.setUserTitle_adclient(self.obj, user, title)

      def setUserDepartment(self, user, department):
          _adclient.setUserDepartment_adclient(self.obj, user, department)

      def setUserCompany(self, user, company):
          _adclient.setUserCompany_adclient(self.obj, user, company)

      def setUserPhone(self, user, phone):
          _adclient.setUserPhone_adclient(self.obj, user, phone)

      def UnlockUser(self, user):
          _adclient.UnlockUser_adclient(self.obj, user)

      def get_error_num(self):
          return _adclient.get_error_num()
