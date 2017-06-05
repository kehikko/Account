<?php

/**
 * UserEntity
 */
class UserEntity
{
	/**
	 * @var integer
	 */
	private $id;

	/**
	 * @var string
	 */
	private $username;

	/**
	 * @var string
	 */
	private $password;

	/**
	 * @var string
	 */
	private $email;

	/**
	 * @var string
	 */
	private $name;

	/**
	 * @var string
	 */
	private $roles;

	/**
	 * @var string
	 */
	private $lang;

	/**
	 * Get id
	 *
	 * @return integer
	 */
	public function getId()
	{
		return $this->id;
	}

	/**
	 * Set username
	 *
	 * @param  string       $username
	 * @return UserEntity
	 */
	public function setUsername($username)
	{
		$this->username = $username;

		return $this;
	}

	/**
	 * Get username
	 *
	 * @return string
	 */
	public function getUsername()
	{
		return $this->username;
	}

	/**
	 * Set password
	 *
	 * @param  string       $password
	 * @return UserEntity
	 */
	public function setPassword($password)
	{
		$this->password = $password;

		return $this;
	}

	/**
	 * Get password
	 *
	 * @return string
	 */
	public function getPassword()
	{
		return $this->password;
	}

	/**
	 * Set email
	 *
	 * @param  string       $email
	 * @return UserEntity
	 */
	public function setEmail($email)
	{
		$this->email = $email;

		return $this;
	}

	/**
	 * Get email
	 *
	 * @return string
	 */
	public function getEmail()
	{
		return $this->email;
	}

	/**
	 * Set name
	 *
	 * @param  string       $name
	 * @return UserEntity
	 */
	public function setName($name)
	{
		$this->name = $name;

		return $this;
	}

	/**
	 * Get name
	 *
	 * @return string
	 */
	public function getName()
	{
		return $this->name;
	}

	/**
	 * Set roles
	 *
	 * @param  string       $roles
	 * @return UserEntity
	 */
	public function setRoles($roles)
	{
		$this->roles = $roles;

		return $this;
	}

	/**
	 * Get roles
	 *
	 * @return string
	 */
	public function getRoles()
	{
		return $this->roles;
	}

	/**
	 * Set lang
	 *
	 * @param  string       $lang
	 * @return UserEntity
	 */
	public function setLang($lang)
	{
		$this->lang = $lang;

		return $this;
	}

	/**
	 * Get lang
	 *
	 * @return string
	 */
	public function getLang()
	{
		return $this->lang;
	}
}
