<?php

namespace Account\Yaml;
use kernel;
use Exception403;
use Exception500;

/**
 * Simple user class.
 */
class Account extends \Account\Account
{
	private $hash   = null;
	private $passwd = null;

	public function __construct($username = false, $password = false)
	{
		parent::__construct($username);

		/* setup passwd file location */
		$passwd = $this->getModuleValue('passwd');
		if (!$passwd)
		{
			$passwd = '{path:config}/passwd';
		}
		$this->passwd = $this->kernel->expand($passwd);
		if (!is_file($this->passwd))
		{
			if (@touch($this->passwd) !== true)
			{
				$error = error_get_last();
				throw new Exception500('Unable to create default passwd file: ' . $this->passwd . ', reason: ' . $error['message']);
			}
			chmod($this->passwd, 0600);
		}

		/* empty user */
		if ($username === false)
		{
			return;
		}

		/* load users and check that requested user exists */
		$users = $this->usersLoad();
		if (!isset($users[$username]))
		{
			throw new Exception403('Access denied.');
		}
		$userdata = $users[$username];

		/* save password hash privately for later use */
		if (isset($userdata['password']))
		{
			$this->hash = $userdata['password'];
		}

		/* check password if given */
		if ($password !== false)
		{
			/* check password */
			if (!$this->checkPassword($password))
			{
				throw new Exception403('Access denied.');
			}
		}

		/* setup user information */
		foreach ($userdata as $key => $value)
		{
			$this->set($key, $value);
		}
	}

	public function create($username, $password = false)
	{
		/* check that user does not exist */
		if ($this->kernel->session->getUser($username))
		{
			return false;
		}

		$users = $this->usersLoad();

		/* create user */
		$userdata = array(
			'email' => '',
			'name'  => '',
			'roles' => array(),
			'lang'  => $this->kernel->lang,
		);
		$users[$username] = $userdata;

		$this->usersSave($users);

		$user = new self($username);

		/* emit user create */
		$this->emit(__FUNCTION__, $user);

		/* only set password if it was given */
		if (is_string($password))
		{
			$user->setPassword($password);
		}

		return $user;
	}

	public function delete()
	{
		$username = $this->get('username');

		/* load users and check that user does exist */
		$users = $this->usersLoad();
		if (!isset($users[$username]))
		{
			return false;
		}

		/* delete from passwd file */
		$r = $this->passwdModifyUser($this->passwd, $username, null);
		if ($r !== true)
		{
			return false;
		}

		unset($users[$username]);
		$this->usersSave($users);

		/* emit user delete */
		$this->emit(__FUNCTION__, $this);

		return true;
	}

	public function checkPassword($password)
	{
		$username = $this->get('username');

		$r = self::passwdVerify($this->passwd, $username, $password);
		if ($r === true)
		{
			return true;
		}

		return false;
	}

	public function setPassword($password)
	{
		$users    = $this->usersLoad();
		$username = $this->get('username');
		if (!isset($users[$username]))
		{
			throw new ErrorException('Invalid username.');
		}

		$r = $this->passwdModifyUser($this->passwd, $username, $password);
		if ($r !== true)
		{
			return false;
		}

		/* emit user password change */
		$this->emit(__FUNCTION__, $this);

		return true;
	}

	public function saveUserdata()
	{
		$users    = $this->usersLoad();
		$username = $this->get('username');
		if (!isset($users[$username]))
		{
			throw new ErrorException('Invalid username.');
		}

		$hash = null;
		if (isset($users[$username]['password']))
		{
			$hash = $users[$username]['password'];
		}

		$users[$username] = $this->getUserdata();
		if ($hash)
		{
			$users[$username]['password'] = $hash;
		}

		$this->usersSave($users);

		/* emit user data save */
		$this->emit(__FUNCTION__, $this);
	}

	/**
	 * Get all users as user objects.
	 *
	 * @return array All users as array of objects, username as key.
	 */
	public function getUsers()
	{
		$usersdata = $this->usersLoad();
		$users     = array();
		foreach ($usersdata as $username => $userdata)
		{
			$users[$username] = new self($username);
		}
		return $users;
	}

	private function usersLoad()
	{
		$file = $this->getModuleValue('file');
		if (!$file)
		{
			$file = '{path:config}/users.yaml';
		}
		$file = $this->kernel->expand($file);
		if (!file_exists($file))
		{
			$this->kernel->log(LOG_ERR, 'user yaml file not found: ' . $file);
			return array();
		}

		$users = kernel::yaml_read($file);
		if (!$users)
		{
			throw new ErrorException('Failed to load user yaml file.');
		}

		return $users;
	}

	private function usersSave($data)
	{
		$file = $this->getModuleValue('file');
		if (!$file)
		{
			$file = '{path:config}/users.yaml';
		}
		$file = $this->kernel->expand($file);
		kernel::yaml_write($file, $data);
	}
}
