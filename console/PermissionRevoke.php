<?php

namespace Acorn\Console;

class PermissionRevoke extends PermissionCommandBase
{
    /**
     * @var string The console command name.
     */
    protected static $defaultName = 'acorn:permission-revoke';

    /**
     * @var string The name and signature of this command.
     */
    protected $signature = 'acorn:permission-revoke
        {target : Role code/name or user login/email}
        {permission : Exact permission code, table/column, or just table}
        {--role : Force target to be looked up as a role}
        {--user : Force target to be looked up as a user}
        {--action= : Narrow a table/table-column lookup, e.g. create, update, delete, view_menu, manage_all}';

    /**
     * @var string The console command description.
     */
    protected $description = 'Revoke a permission from a role or user, resolved by name';

    protected function applyToPermissions(array &$permissions, string $code): void
    {
        unset($permissions[$code]);
    }

    protected function pastTenseVerb(): string
    {
        return 'Revoked';
    }
}
