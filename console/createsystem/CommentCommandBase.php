<?php

namespace Acorn\Console\CreateSystem;

use DB;
use Acorn\Comment;
use Acorn\Console\Command;
use Exception;

/**
 * Shared machinery for the acorn:cs:* comment-management commands.
 *
 * A "target" is always resolved in two stages:
 *   1. {table} -- a table name, optionally with * wildcards (translated to
 *      SQL LIKE %). Always scoped to domain_data.fifteen_commerce_pa_* and
 *      public.fifteen_* tables (the only ones these commands are meant for).
 *      If {table} matches no table AND --column is omitted, it's checked
 *      against schema names (exact match, no wildcard) as a fallback -- so
 *      `comment-set domain_data schema-editable=true` sets a SCHEMA-level
 *      comment instead of erroring.
 *   2. --column=<name> (also wildcard-capable) -- narrows to one or more
 *      columns on each matched table. Omit for a table-level comment.
 *      Combine with --fk to target that column's FK CONSTRAINT instead of
 *      the column itself -- these are DIFFERENT comments with DIFFERENT
 *      effects (see CreateSystemExclude for why this distinction matters).
 *
 * Whenever a lookup matches more than one target -- which wildcards make
 * routine, not exceptional -- every match is printed and the user is asked
 * to confirm before anything is written. Never overwrites an existing
 * comment: always parses it as YAML, merges the new keys in (top-level key
 * replace, everything else preserved), and re-serialises.
 */
abstract class CommentCommandBase extends Command
{
    protected function resolveTargets(string $tablePattern, ?string $columnPattern, bool $fk, bool $requireConfirmation = true): array
    {
        $tableLike = $this->wildcardToLike($tablePattern);

        $tables = DB::select(
            "SELECT table_schema, table_name FROM information_schema.tables
             WHERE table_type = 'BASE TABLE'
               AND table_schema IN ('domain_data', 'public')
               AND table_name LIKE ?
             ORDER BY table_schema, table_name",
            [$tableLike]
        );

        if (empty($tables)) {
            if ($columnPattern === null) {
                $schemaExists = DB::selectOne(
                    "SELECT nspname FROM pg_namespace WHERE nspname = ?",
                    [$tablePattern]
                );
                if ($schemaExists) {
                    $this->info("[{$tablePattern}] is a schema, not a table -- targeting it at the schema level.");
                    return [['type' => 'schema', 'schema' => $tablePattern]];
                }
            }
            throw new Exception("No table matches [{$tablePattern}], and it isn't a schema name either.");
        }

        $targets = [];

        if ($columnPattern === null) {
            foreach ($tables as $t) {
                $targets[] = ['type' => 'table', 'schema' => $t->table_schema, 'table' => $t->table_name];
            }
            return $this->confirmTargets($targets, $requireConfirmation);
        }

        $columnLike = $this->wildcardToLike($columnPattern);

        foreach ($tables as $t) {
            $columns = DB::select(
                "SELECT column_name FROM information_schema.columns
                 WHERE table_schema = ? AND table_name = ? AND column_name LIKE ?
                 ORDER BY column_name",
                [$t->table_schema, $t->table_name, $columnLike]
            );

            foreach ($columns as $c) {
                if ($fk) {
                    $constraint = DB::selectOne(
                        "SELECT con.conname FROM pg_constraint con
                         JOIN pg_class cl ON cl.oid = con.conrelid
                         JOIN pg_namespace n ON n.oid = cl.relnamespace
                         JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = ANY(con.conkey)
                         WHERE n.nspname = ? AND cl.relname = ? AND a.attname = ? AND con.contype = 'f'",
                        [$t->table_schema, $t->table_name, $c->column_name]
                    );
                    if (!$constraint) {
                        continue; // not an FK column, --fk doesn't apply
                    }
                    $targets[] = [
                        'type' => 'constraint',
                        'schema' => $t->table_schema,
                        'table' => $t->table_name,
                        'column' => $c->column_name,
                        'constraint' => $constraint->conname,
                    ];
                } else {
                    $targets[] = [
                        'type' => 'column',
                        'schema' => $t->table_schema,
                        'table' => $t->table_name,
                        'column' => $c->column_name,
                    ];
                }
            }
        }

        if (empty($targets)) {
            $desc = $fk ? "FK columns" : "columns";
            throw new Exception("No matching {$desc} found for [{$tablePattern}" . ($columnPattern ? ".{$columnPattern}" : '') . "].");
        }

        return $this->confirmTargets($targets, $requireConfirmation);
    }

    protected function wildcardToLike(string $pattern): string
    {
        // User wildcards are * (matches like a fresh eye would expect);
        // escape real SQL LIKE metacharacters first so they're literal.
        $escaped = str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $pattern);
        return str_replace('*', '%', $escaped);
    }

    /**
     * Print every resolved target and require confirmation before
     * proceeding whenever there's more than one -- wildcards make this the
     * normal case, not an edge case, so it always shows the full list.
     */
    protected function confirmTargets(array $targets, bool $requireConfirmation = true): array
    {
        if (count($targets) === 1) {
            return $targets;
        }

        $this->warn(count($targets) . " targets matched:");
        foreach ($targets as $t) {
            $this->line('  ' . $this->describeTarget($t));
        }

        if ($requireConfirmation && !$this->confirm('Proceed with all ' . count($targets) . ' of these?')) {
            throw new Exception('Aborted.');
        }

        return $targets;
    }

    protected function describeTarget(array $t): string
    {
        return match ($t['type']) {
            'schema' => "{$t['schema']} (schema)",
            'table' => "{$t['schema']}.{$t['table']} (table)",
            'column' => "{$t['schema']}.{$t['table']}.{$t['column']} (column)",
            'constraint' => "{$t['constraint']} on {$t['schema']}.{$t['table']} (FK constraint, column {$t['column']})",
        };
    }

    protected function getExistingComment(array $target): ?string
    {
        return Comment::read($target);
    }

    /**
     * Merge new keys into an existing YAML comment (parsed to array,
     * top-level keys overwritten, everything else preserved, re-serialised)
     * -- never a blind string append, so re-running with the same key
     * updates it in place instead of duplicating it.
     */
    protected function mergeComment(?string $existing, array $newKeys): string
    {
        return Comment::merge($existing, $newKeys);
    }

    protected function applyComment(array $target, string $comment): void
    {
        Comment::apply($target, $comment);
    }

    /**
     * Parse a list of key=value CLI arguments into a nested array, ready
     * for mergeComment(). Recognises true/false/null/numeric scalars;
     * everything else stays a string.
     */
    protected function parseAssignments(array $assignments): array
    {
        $out = [];
        foreach ($assignments as $assignment) {
            if (!str_contains($assignment, '=')) {
                throw new Exception("Expected key=value, got [{$assignment}].");
            }
            [$key, $value] = explode('=', $assignment, 2);
            $out[$key] = $this->coerceScalar($value);
        }
        return $out;
    }

    protected function coerceScalar(string $value)
    {
        return match (strtolower($value)) {
            'true' => true,
            'false' => false,
            'null' => null,
            default => is_numeric($value) ? $value + 0 : $value,
        };
    }
}
