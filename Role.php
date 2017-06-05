<?php

namespace Account;
use Exception;

/**
 * Basic role class.
 */
abstract class Role extends \Core\Module
{
	/* list of roles */
	protected $roles = array();

	public function __construct()
	{
		parent::__construct();

		/* load custom roles from config */
		try
		{
			$roles = $this->kernel->getConfigValue('setup', 'roles');
			if (is_array($roles))
			{
				foreach ($roles as $role => $info)
				{
					$this->addRole($role, $info);
				}
			}
		}
		catch (Exception $e)
		{

		}

		/* setup default roles */
		$roles = array(
			'admin' => array(
				'type'        => 'role',
				'title'       => '{tr:roles/admin/title}',
				'description' => '{tr:roles/admin/description}',
			),
			'user'  => array(
				'type'        => 'role',
				'title'       => '{tr:roles/user/title}',
				'description' => '{tr:roles/user/description}',
			),
			'root'  => array(
				'type'        => 'role',
				'title'       => '{tr:roles/root/title}',
				'description' => '{tr:roles/root/description}',
			),
		);
		foreach ($roles as $role => $info)
		{
			$this->addRole($role, $info);
		}
	}

	public function getAll()
	{
		return $this->roles;
	}

	protected function addRole($role, $info)
	{
		if (!isset($info['type']) || !is_string($role))
		{
			return false;
		}

		$info['role'] = $info['type'] . ':' . $role;
		$info['name'] = $role;

		if (!isset($info['title']))
		{
			$info['title'] = $info['role'];
		}
		else
		{
			$info['title'] = $this->kernel->expand($info['title']);
		}

		if (!isset($info['description']))
		{
			$info['description'] = '';
		}
		else
		{
			$info['description'] = $this->kernel->expand($info['description']);
		}

		$this->roles[$role] = $info;

		return true;
	}
}
