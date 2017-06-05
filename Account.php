<?php

namespace Account;
use kernel;
use ErrorException;

/**
 * Basic user authenticator class.
 */
abstract class Account extends \Core\Module
{
	/* as default, store values here */
	private $values = array();
	/* some value cannot be set */
	private $constants = array('username', 'password');

	public function __construct($username)
	{
		parent::__construct();
		$this->values['username'] = $username;
		$this->values['lang']     = $this->kernel->lang;
	}

	/**
	 * Implement this.
	 */
	abstract public function create($username);

	/**
	 * Implement this.
	 */
	abstract public function delete();

	/**
	 * Implement this.
	 */
	abstract public function checkPassword($password);

	/**
	 * Implement this.
	 */
	abstract public function setPassword($password);

	/**
	 * Implement this.
	 */
	abstract public function saveUserdata();

	/**
	 * Implement this.
	 */
	abstract public function getUsers();

	public function getUserdata()
	{
		$values = array();
		foreach ($this->values as $key => $value)
		{
			if (in_array($key, $this->constants))
			{
				continue;
			}
			$values[$key] = $value;
		}
		return $values;
	}

	public function get($key)
	{
		if ($key == 'name' && empty($this->values[$key]))
		{
			return $this->get('username');
		}
		if (isset($this->values[$key]))
		{
			return $this->values[$key];
		}
		return null;
	}

	public function set($key, $value)
	{
		if (in_array($key, $this->constants))
		{
			return false;
		}

		$this->values[$key] = $value;
		return true;
	}

	public function getRoles()
	{
		$roles = $this->get('roles');
		if (!$roles)
		{
			return array();
		}
		return self::expandRoles($roles);
	}

	public function addRole($role)
	{
		$roles = $this->getRoles();
		if (!in_array($role, $roles))
		{
			$roles[] = $role;
			$this->set('roles', implode(',', $roles));
			/* emit role add */
			$this->emit(__FUNCTION__, $this, $role);
			$this->saveUserdata();
		}
		return true;
	}

	public function removeRole($role)
	{
		$roles = $this->getRoles();
		if (in_array($role, $roles))
		{
			foreach ($roles as $key => $r)
			{
				if ($r == $role)
				{
					unset($roles[$key]);
					break;
				}
			}
			$this->set('roles', implode(',', $roles));
			/* emit role remove */
			$this->emit(__FUNCTION__, $this, $role);
			$this->saveUserdata();
		}
		return true;
	}

	public function hasRole($role)
	{
		if (strlen($this->get('username')) > 0 && $role == 'role:user')
		{
			return true;
		}
		if (in_array($role, $this->getRoles()))
		{
			return true;
		}
		return false;
	}

	public function toArray()
	{
		return $this->values;
	}

	public static function expandRoles($str_roles)
	{
		if (is_array($str_roles))
		{
			return $str_roles;
		}
		$roles = array();
		if (is_object($str_roles))
		{
			foreach ($str_roles as $role)
			{
				$roles[] = trim($role);
			}
		}
		else
		{
			foreach (explode(',', $str_roles) as $role)
			{
				if (strlen($role) < 1)
				{
					continue;
				}
				$roles[] = trim($role);
			}
		}
		return $roles;
	}

	public static function passwordHash($username, $password)
	{
		// return password_hash($password, PASSWORD_DEFAULT);
		return crypt($password, '$6$' . \Core\Compose::unique(8) . '$');
	}

	public static function passwordVerify($username, $password, $hash)
	{
		/* empty user cannot authenticate */
		if (!$username)
		{
			return false;
		}

		return trim($hash) == trim(crypt($password, $hash)) ? true : false;
	}

	public static function passwdModifyUser($passwd_file, $username, $password)
	{
		$kernel = kernel::getInstance();
		if (!file_exists($passwd_file))
		{
			if (!@touch($passwd_file))
			{
				$kernel->log(LOG_CRIT, 'Unable to create passwd-file "' . $passwd_file . '" when calling ' . __METHOD__ . '!');
				throw new ErrorException('Internal error, unable to create file in ' . __FUNCTION__);
			}
		}
		$data = @file($passwd_file);
		if ($data === false)
		{
			$kernel->log(LOG_CRIT, 'Unable to read passwd-file "' . $passwd_file . '" when calling ' . __METHOD__ . '!');
			throw new ErrorException('Internal error, unable to read file in ' . __FUNCTION__);
		}

		/* if user should be removed */
		if ($password === null)
		{
			foreach ($data as $k => $line)
			{
				$u = strtok($line, ':');
				if ($u == $username)
				{
					unset($data[$k]);
					break;
				}
			}
		}
		else
		{
			$user_hash = $username . ':' . self::passwordHash($username, $password);
			$found     = false;
			foreach ($data as $k => $line)
			{
				$u = strtok($line, ':');
				if ($u == $username)
				{
					$found   = true;
					$oldhash = strtok(':');
					$rest    = strtok(null);
					if (empty($rest))
					{
						$data[$k] = $user_hash . "\n";
					}
					else
					{
						$data[$k] = $user_hash . ':' . trim($rest) . "\n";
					}
					break;
				}
			}
			if (!$found)
			{
				$data[] = $user_hash . "\n";
			}
		}

		$f = fopen($passwd_file, 'w');
		if (!$f)
		{
			$kernel->log(LOG_CRIT, 'Unable to write passwd-file "' . $passwd_file . '" when calling ' . __METHOD__ . '!');
			throw new ErrorException('Internal error, unable to write file in ' . __FUNCTION__);
		}
		foreach ($data as $line)
		{
			fwrite($f, $line);
		}
		fclose($f);

		return true;
	}

	public function passwdVerify($passwd_file, $username, $password)
	{
		$kernel = kernel::getInstance();
		$data   = @file($passwd_file);
		if (!$data)
		{
			$kernel->log(LOG_CRIT, 'Unable to read passwd-file "' . $passwd_file . '" when calling ' . __METHOD__ . '!');
			return false;
		}

		/* find user hash */
		$hash = null;
		foreach ($data as $k => $line)
		{
			$u = strtok($line, ':');
			if ($u == $username)
			{
				$hash = strtok(':');
				break;
			}
		}
		/* user not found */
		if (!$hash)
		{
			return false;
		}

		/* hack to check htpasswd style APR1-MD5 hashes */
		if (strpos($hash, '$apr1$') === 0)
		{
			$cmd = 'htpasswd -b -m -v ' . escapeshellarg($passwd_file) . ' ' . escapeshellarg($username) . ' ' . escapeshellarg($password);
			exec($cmd, $output, $r);
			if ($r === 0)
			{
				return true;
			}
			return false;
		}

		/* try to match */
		return $this->passwordVerify($username, $password, $hash);
	}
}
