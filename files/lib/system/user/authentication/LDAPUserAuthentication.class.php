<?php
/* LDAPUserAuthentication.class.php - be.bastelstu.jan.wcf.ldap
 * Copyright (C) 2013 Jan Altensen (Stricted)
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>. 
 */
// imports
namespace wcf\system\user\authentication;
use wcf\data\user\group\UserGroup;
use wcf\data\user\UserAction;
use wcf\data\user\User;
use wcf\data\user\UserEditor;
use wcf\data\user\UserProfileAction;
use wcf\system\exception\SystemException;
use wcf\system\exception\UserInputException;
use wcf\util\HeaderUtil;
use wcf\util\PasswordUtil;
use wcf\util\LDAPUtil;
use wcf\util\UserUtil;
use wcf\system\language\LanguageFactory;
use wcf\system\WCF;

class LDAPUserAuthentication extends DefaultUserAuthentication {
	protected $email = '';
	protected $username = '';

	/**
	 * Checks the given user data.
	 *
	 * @param	string		$username
	 * @param 	string		$password
	 * @return	boolean
	 */
	protected function checkWCFUser($username, $password) {
		if($this->isValidEmail($username))
			$user = User::getUserByEmail($username);
		else
			$user = User::getUserByUsername($username);
		
		if ($user->userID != 0) {
			if ($user->checkPassword($password)) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Checks the given user data.
	 *
	 * @param	string		$username
	 * @param 	string		$password
	 * @return	boolean
	 */
	protected function checkLDAPUser($username, $password) {
		$ldap = new LDAPUtil();
		// connect
		$connect = $ldap->connect(LDAP_SERVER, LDAP_SERVER_PORT, LDAP_DN);
		if ($connect) {
			// find user
			if ($ldap->bind("uid=".$username, $password)) {
				// try to find user email
				$search = $ldap->search('uid='.$username);
				if ($search) {
					$results = $ldap->get_entries($search);
					if (isset($results[0]['mail'][0])) {
						$this->email = $results[0]['mail'][0];
						$ldap->close();
						return true;
					}
				}
			} elseif ($this->isValidEmail($username) && ($search = $ldap->search('mail='.$username))) {
				$results = $ldap->get_entries($search);
				if(isset($results[0]['uid'][0])) {
					$this->username = $results[0]['uid'][0];
					$ldap->close($connect);
					return $this->checkLDAPUser($this->username, $password);
				}
			}
		}
		// no ldap user or connection -> check user from wcf
		$ldap->close($connect);
		if(LDAP_CHECK_WCF) {
			return $this->checkWCFUser($username, $password);
		}
		return false;
	}

	/**
	 * @see IUserAuthentication::loginManually()
	 */
	public function loginManually($username, $password, $userClassname = 'wcf\data\user\User') {
		if (!$this->checkLDAPUser($username, $password)) {
			throw new UserInputException('password', 'false');
		}
		if(!empty($this->username)) {
			$username = $this->username;
		}
		if($this->isValidEmail($username))
			$user = User::getUserByEmail($username);
		else
			$user = User::getUserByUsername($username);
		
		if ($user->userID == 0) {
			// create user
			if(!empty($this->email) && isset($this->email)) {
				$groupIDs = UserGroup::getGroupIDsByType(array(UserGroup::EVERYONE, UserGroup::GUESTS, UserGroup::USERS));
				$languageID = array(LanguageFactory::getInstance()->getDefaultLanguageID());
				$addDefaultGroups = true;
				$saveOptions = array();
				$additionalFields = array();
				$additionalFields['languageID'] = WCF::getLanguage()->languageID;
				$additionalFields['registrationIpAddress'] = WCF::getSession()->ipAddress;
				$data = array(
					'data' => array_merge($additionalFields, array(
						'username' => $username,
						'email' => $this->email,
						'password' => $password,
					)),
					'groups' => $groupIDs,
					'languages' => $languageID,
					'options' => $saveOptions,
					'addDefaultGroups' => $addDefaultGroups
				);
				
				$objectAction = new UserAction(array(), 'create', $data);
				$result = $objectAction->executeAction();
				$user = $result['returnValues'];
				$userEditor = new UserEditor($user);

				// update user rank
				if (MODULE_USER_RANK) {
					$action = new UserProfileAction(array($userEditor), 'updateUserRank');
					$action->executeAction();
				}
				// update user online marking
				$action = new UserProfileAction(array($userEditor), 'updateUserOnlineMarking');
				$action->executeAction();

			} else {
				throw new UserInputException('password', 'false');
			}
		}
		
		return $user;
	}
	
	/**
	 * @see IUserAuthentication::storeAccessData()
	 */
	public function storeAccessData(User $user, $username, $password) {
		HeaderUtil::setCookie('userID', $user->userID, TIME_NOW + 365 * 24 * 3600);
		HeaderUtil::setCookie('password', PasswordUtil::getSaltedHash($password, $user->password), TIME_NOW + 365 * 24 * 3600);
	}

	/**
	 * Validates the cookie password.
	 * 
	 * @param	User		$user
	 * @param	string		$password
	 * @return	boolean
	 */
	protected function checkCookiePassword($user, $password) {
		return $user->checkCookiePassword($password);
	}
	
	/**
	 * Returns true if the given e-mail is a valid address.
	 * 
	 * @param	string		$email
	 * @return	boolean
	 */
	protected function isValidEmail($email) {
		return UserUtil::isValidEmail($email);
	}
}
?>