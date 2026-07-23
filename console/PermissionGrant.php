<?php

namespace Acorn\Console;

class PermissionGrant extends PermissionCommandBase
{
    /**
     * @var string The console command name.
     */
    protected static $defaultName = 'acorn:permission-grant';

    /**
     * @var string The name and signature of this command.
     */
    protected $signature = 'acorn:permission-grant
        {target : Role code/name or user login/email}
        {permission : Exact permission code, table/column, or just table}
        {--role : Force target to be looked up as a role}
        {--user : Force target to be looked up as a user}
        {--action= : Narrow a table/table-column lookup, e.g. create, update, delete, view_menu, manage_all}';

    /**
     * @var string The console command description.
     */
    protected $description = 'Grant a permission to a role or user, resolved by name';

    protected function applyToPermissions(array &$permissions, string $code): void
    {
        $permissions[$code] = '1';
    }

    protected function pastTenseVerb(): string
    {
        return 'Granted';
    }
}
