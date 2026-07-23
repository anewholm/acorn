<?php

namespace Acorn\Console;

use Backend\Facades\BackendAuth;
use Backend\Models\User;
use Backend\Models\UserRole;
use Winter\Storm\Console\Command;
use Winter\Storm\Support\Str;
use Exception;

/**
 * Shared resolution logic for acorn:permission-grant / acorn:permission-revoke.
 *
 * Both commands accept:
 *   {target}     A role code/name, or a user login/email. Whichever matches
 *                is used; pass --role or --user to force a category if the
 *                same name could plausibly mean either.
 *   {permission} Any of:
 *                  - an exact permission code, e.g. fifteen.commerce.paconsumable_create
 *                  - table/column, e.g. paconsumable/material or pa_colours/name
 *                  - just a table, e.g. pacolours or fifteen_commerce_pa_colours
 *                Table tokens accept the DB table name, the squished plural
 *                controller slug, or the squished singular model key -- all
 *                three resolve to the same family of permission codes.
 *   --action=    Narrows table/table-column lookups to codes ending in
 *                _<action> or .<action> (e.g. create, update, delete,
 *                view_menu, manage_all). Required whenever the lookup would
 *                otherwise be ambiguous.
 *
 * Errors (does not guess) when a lookup matches zero or more than one
 * target/permission -- ambiguous matches are listed so the caller can narrow
 * with --role/--user or --action.
 */
abstract class PermissionCommandBase extends Command
{
    /** Set to '1' by grant, unset by revoke. */
    abstract protected function applyToPermissions(array &$permissions, string $code): void;

    /** Present-tense verb for confirmation output, e.g. "Granted"/"Revoked". */
    abstract protected function pastTenseVerb(): string;

    public function handle()
    {
        try {
            [$model, $kind] = $this->resolveTarget(
                $this->argument('target'),
                $this->option('role'),
                $this->option('user')
            );

            $code = $this->resolvePermissionCode(
                $this->argument('permission'),
                $this->option('action')
            );
        } catch (Exception $e) {
            $this->error($e->getMessage());
            return 1;
        }

        $permissions = $model->permissions ?: [];
        $this->applyToPermissions($permissions, $code);
        $model->permissions = $permissions;
        $model->save();

        $targetLabel = $kind === 'role' ? "role [{$model->code}]" : "user [{$model->login}]";
        $this->info("{$this->pastTenseVerb()} {$code} for {$targetLabel}");
        return 0;
    }

    /**
     * Resolve {target} to a UserRole or User model by name, erroring on
     * zero or multiple matches. --role/--user force which table is searched;
     * omit both to search roles then users and error if both match.
     */
    protected function resolveTarget(string $identifier, ?bool $roleFlag, ?bool $userFlag): array
    {
        if ($roleFlag && $userFlag) {
            throw new Exception("Pass at most one of --role / --user, not both.");
        }

        $roleMatches = $userFlag ? collect() : $this->findRoles($identifier);
        $userMatches = $roleFlag ? collect() : $this->findUsers($identifier);

        if ($roleMatches->count() > 1) {
            $names = $roleMatches->pluck('code')->implode(', ');
            throw new Exception("Ambiguous role [{$identifier}] matches: {$names}");
        }
        if ($userMatches->count() > 1) {
            $names = $userMatches->pluck('login')->implode(', ');
            throw new Exception("Ambiguous user [{$identifier}] matches: {$names}");
        }
        if ($roleMatches->count() === 1 && $userMatches->count() === 1) {
            throw new Exception(
                "[{$identifier}] matches both a role ({$roleMatches->first()->code}) ".
                "and a user ({$userMatches->first()->login}) -- pass --role or --user to disambiguate."
            );
        }
        if ($roleMatches->count() === 1) {
            return [$roleMatches->first(), 'role'];
        }
        if ($userMatches->count() === 1) {
            return [$userMatches->first(), 'user'];
        }

        throw new Exception("No role or user found matching [{$identifier}].");
    }

    protected function findRoles(string $identifier)
    {
        return UserRole::where('code', $identifier)
            ->orWhere('name', $identifier)
            ->get();
    }

    protected function findUsers(string $identifier)
    {
        return User::where('login', $identifier)
            ->orWhere('email', $identifier)
            ->get();
    }

    /**
     * Resolve {permission} to a single permission code, erroring on zero or
     * multiple matches.
     */
    protected function resolvePermissionCode(string $lookup, ?string $action): string
    {
        $all = collect(BackendAuth::instance()->listPermissions())->pluck('code');

        // 1. Exact match -- the literal permission code.
        if ($all->contains($lookup)) {
            return $lookup;
        }

        // 2. table/column or just table.
        [$table, $column] = str_contains($lookup, '/')
            ? explode('/', $lookup, 2)
            : [$lookup, null];

        $tableTerms = $this->tableSearchTerms($table);

        $matches = $all->filter(function ($code) use ($tableTerms, $column, $action) {
            $codeLower = strtolower($code);
            $rest = preg_replace('/^[a-z0-9]+\.[a-z0-9]+\./', '', $codeLower);

            // Model-key/table component is everything up to the first
            // underscore or dot -- squished keys never contain either, so
            // this boundary is exact. Must match a search term EXACTLY
            // (not just contain it) or e.g. "pacolour" would wrongly match
            // "pacolouredtape_..." (an unrelated table with a shared prefix).
            if (!preg_match('/^([a-z0-9]+)/', $rest, $m)) {
                return false;
            }
            if (!in_array($m[1], $tableTerms, true)) {
                return false;
            }

            if ($column && !str_contains($codeLower, strtolower($column))) {
                return false;
            }

            if ($action && !preg_match('/[._]' . preg_quote(strtolower($action), '/') . '$/', $codeLower)) {
                return false;
            }

            return true;
        })->values();

        if ($matches->isEmpty()) {
            $desc = $column ? "table [{$table}] column [{$column}]" : "table [{$table}]";
            $suffix = $action ? " action [{$action}]" : '';
            throw new Exception("No permission found for {$desc}{$suffix}.");
        }

        if ($matches->count() > 1) {
            throw new Exception(
                "Ambiguous permission lookup [{$lookup}]" . ($action ? " action [{$action}]" : '') .
                " matches:\n  " . $matches->implode("\n  ") .
                "\nNarrow with --action=<view_menu|create|update|delete|view_all_fields|change_all_fields|manage_all|...>" .
                " or use the exact permission code."
            );
        }

        return $matches->first();
    }

    /**
     * A table token may be the raw DB table name, the fifteen_commerce_*
     * prefixed form, the squished plural controller slug, or the squished
     * singular model key. Permission codes only ever use the squished
     * singular/plural forms with no underscores, so normalise and offer
     * both number forms as candidate substrings.
     */
    protected function tableSearchTerms(string $table): array
    {
        $stripped = preg_replace('/^fifteen[._]commerce[._]/', '', strtolower($table));
        $squished = str_replace('_', '', $stripped);

        $singular = strtolower(Str::singular($squished));
        $plural   = strtolower(Str::plural($singular));

        return array_unique([$squished, $singular, $plural]);
    }
}
