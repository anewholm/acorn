<?php namespace Acorn\Traits;

use Backend\Facades\BackendAuth;
use \Illuminate\Auth\Access\AuthorizationException;

trait LinuxPermissions
{
    public static $READ   = 1;
    public static $WRITE  = 2;
    public static $DELETE = 4;

    public static $USER   = 1;
    public static $GROUP  = 8;
    public static $OTHER  = 64;

    protected function can(int $accessType)
    {
        // Acorn\User is an optional plugin; if absent, skip permission checks
        if (!class_exists('Acorn\User\Models\User')) return true;
        $user = \Acorn\User\Models\User::authUser();
        if (is_null($user)) return true;
        $groups  = $user->groups->keyBy('id');

        $noOwner = is_null($this->owner_user);
        $isOwner = ($user->id == $this->owner_user?->id);
        $inGroup = ($groups->get($this->owner_user_group?->id));
        $isSuperUser = $user->is_superuser; // Redirected attribute to the backend user

        return $isSuperUser
            || $noOwner
            || ($isOwner && $this->permissions & $accessType * self::$USER)
            || ($inGroup && $this->permissions & $accessType * self::$GROUP)
            ||              $this->permissions & $accessType * self::$OTHER;
    }

    public function permissionsObject()
    {
        return (property_exists($this, 'permissionsObject') ? $this->permissionsObject : $this);
    }

    public function canRead()   { return $this->permissionsObject()->can(self::$READ); }
    public function canWrite()  { return $this->permissionsObject()->can(self::$WRITE); }
    public function canDelete() { return $this->permissionsObject()->can(self::$DELETE); }

    // TODO: SECURITY: Read security
    /*
    public function getAttributes()
    {
        $attributes = parent::getAttributes();

        if (!$this->canRead()) throw new AuthorizationException('Cannot read this object');

        return $attributes;
    }
    */

    // TODO: These are base Model methods so they are incompatible with a Model that also implements them
    // Move all this in to a base class and a Controller::$implement (like Winter does)?
    public function delete()
    {
        if (!$this->canDelete()) throw new AuthorizationException('Cannot delete this object');
        return parent::delete();
    }

    public function fill(array $attributes)
    {
        // This works on the original values, before fill()
        if ($this->attributes && !$this->canWrite()) {
            throw new AuthorizationException('Cannot write this object');
        }
        return parent::fill($attributes);
    }

    public function save(?array $options = [], $sessionKey = null)
    {
        // This works on the new values, because after fill()
        if (!$this->canWrite()) {
            throw new AuthorizationException('Cannot write this object');
        }
        return parent::save($options, $sessionKey);
    }

    public static function dropdownOptions($form = NULL, $field = NULL, bool|NULL $withoutGlobalScopes = FALSE)
    {
        // TODO: Call parent::dropdownOptions() somewhow? These are simple objects?
        $models = self::all();
        $models = $models->filter(function($model): bool
        {
            return $model->canRead();
        });
        return $models->lists('name', 'id');
    }
}
