<?php

namespace Account\Doctrine;

/**
 * UserDoctrine
 */
class Account extends \Account\Account
{
	private $entity = null;
	private $em = null;

	public function __construct($username = false, $password = false)
	{
		parent::__construct($username);
		$this->em = $this->kernel->getEntityManager();

		/* empty user */
		if ($username === false)
		{
			return;
		}

		/* find user from database */
		$user = $this->em->getRepository('UserEntity')->findOneBy(array('username' => $username));
		if (!$user)
		{
			throw new Exception403('Access denied.');
		}
		$this->entity = $user;

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
		$this->set('email', $this->entity->getEmail());
		$this->set('name', $this->entity->getName());
		$this->set('roles', $this->entity->getRoles());
		$this->set('lang', $this->entity->getLang());
	}

	/**
	 * Create new user.
	 */
	public function create($username)
	{
		/* check that user does not exist */
		if ($this->kernel->session->getUser($username))
		{
			return false;
		}

		/* generate random password */
		$password = uniqid();

		/* create user */
		$user = new UserEntity();
		$user->setUsername($username);
		$user->setPassword(self::passwordHash($username, $password));
		$user->setEmail('');
		$user->setName('');
		$user->setRoles('');
		$user->setLang($this->kernel->lang);

		$this->em->persist($user);
		$this->em->flush();

		$user = new self($username, $password);
		
		/* emit user create */
		$this->emit(__FUNCTION__, $user);

		return $user;
	}

	/**
	 * Delete user.
	 */
	public function delete()
	{
		/* emit user delete */
		$this->emit(__FUNCTION__, $this);
		throw new ErrorException('Not implemented.');
	}

	/**
	 * Check password.
	 */
	public function checkPassword($password)
	{
		$username = $this->get('username');
		$hash = $this->entity->getPassword();

		return self::passwordVerify($username, $password, $hash);
	}

	/**
	 * Set password.
	 */
	public function setPassword($password)
	{
		$username = $this->get('username');
		$this->entity->setPassword(self::passwordHash($username, $password));

		$this->em->persist($this->entity);
		$this->em->flush();

		/* emit user password change */
		$this->emit(__FUNCTION__, $this);

		return true;
	}

	/**
	 * Save userdata.
	 */
	public function saveUserdata()
	{
		$this->entity->setEmail($this->get('email'));
		$this->entity->setName($this->get('name'));
		$this->entity->setLang($this->get('lang'));

		$roles = $this->get('roles');
		if (is_array($roles))
		{
			$roles = implode(',', $roles);
		}
		$this->entity->setRoles($roles);

		$this->em->persist($this->entity);
		$this->em->flush();

		/* emit auth user save */
		$this->emit(__FUNCTION__, $this);
	}

	/**
	 * Get all users as user objects.
	 * 
	 * @return array All users as array of objects, username as key.
	 */
	public function getUsers()
	{
		$user_objects = $this->em->getRepository('UserEntity')->findAll();
		$users = array();
		foreach ($user_objects as $user_object)
		{
			$username = $user_object->getUsername();
			$users[$username] = new self($username);
		}
		return $users;
	}

	public function getEntity()
	{
		return $this->entity;
	}
}
