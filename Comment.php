<?php namespace Acorn;

use DB;
use Winter\Storm\Support\Facades\Yaml as YamlParser;
use Symfony\Component\Yaml\Yaml as YamlDumper;
use Exception;

/**
 * Read/merge/write YAML-shaped PostgreSQL COMMENTs on schemas, tables,
 * columns, and FK constraints. Extracted out of
 * Acorn\Console\CreateSystem\CommentCommandBase (which keeps the
 * console-specific target resolution/confirmation UX and delegates the
 * actual comment I/O here) so non-console callers -- e.g.
 * Fifteen\SchemaEditor\Models\Schema\SchemaBase's
 * external_system_target_code mutator -- can read/write these comments
 * without a console context.
 *
 * $target shape: ['type' => 'schema'|'table'|'column'|'constraint',
 *                  'schema' => ..., 'table' => ..., 'column' => ..., 'constraint' => ...]
 */
class Comment
{
    public static function read(array $target): ?string
    {
        return match ($target['type']) {
            'schema' => DB::selectOne(
                "SELECT obj_description(oid, 'pg_namespace') AS c FROM pg_namespace WHERE nspname = ?",
                [$target['schema']]
            )->c ?? null,
            'table' => DB::selectOne(
                "SELECT obj_description(?::regclass) AS c",
                ["{$target['schema']}.{$target['table']}"]
            )->c ?? null,
            'column' => DB::selectOne(
                "SELECT col_description(?::regclass, ordinal_position) AS c
                 FROM information_schema.columns
                 WHERE table_schema = ? AND table_name = ? AND column_name = ?",
                ["{$target['schema']}.{$target['table']}", $target['schema'], $target['table'], $target['column']]
            )->c ?? null,
            'constraint' => DB::selectOne(
                "SELECT obj_description(oid, 'pg_constraint') AS c FROM pg_constraint WHERE conname = ?",
                [$target['constraint']]
            )->c ?? null,
        };
    }

    /**
     * Merge new keys into an existing YAML comment (parsed to array,
     * top-level keys overwritten, everything else preserved, re-serialised)
     * -- never a blind string append, so re-running with the same key
     * updates it in place instead of duplicating it.
     */
    public static function merge(?string $existing, array $newKeys): string
    {
        $data = $existing ? (YamlParser::parse($existing) ?: []) : [];
        if (!is_array($data)) {
            throw new Exception("Existing comment isn't a YAML map, refusing to merge blindly:\n{$existing}");
        }

        foreach ($newKeys as $key => $value) {
            $data = self::setDotted($data, $key, $value);
        }

        return rtrim(YamlDumper::dump($data, 4, 2));
    }

    /** Supports dot-path keys, e.g. has-many-deep-settings.<relation>.field-exclude */
    public static function setDotted(array $data, string $dotKey, $value): array
    {
        $parts = explode('.', $dotKey);
        $cursor = &$data;
        foreach ($parts as $i => $part) {
            if ($i === count($parts) - 1) {
                $cursor[$part] = $value;
            } else {
                if (!isset($cursor[$part]) || !is_array($cursor[$part])) {
                    $cursor[$part] = [];
                }
                $cursor = &$cursor[$part];
            }
        }
        return $data;
    }

    public static function apply(array $target, string $comment): void
    {
        $escaped = str_replace("'", "''", $comment);
        $sql = match ($target['type']) {
            'schema' => "COMMENT ON SCHEMA {$target['schema']} IS '{$escaped}'",
            'table' => "COMMENT ON TABLE {$target['schema']}.{$target['table']} IS '{$escaped}'",
            'column' => "COMMENT ON COLUMN {$target['schema']}.{$target['table']}.{$target['column']} IS '{$escaped}'",
            'constraint' => "COMMENT ON CONSTRAINT {$target['constraint']} ON {$target['schema']}.{$target['table']} IS '{$escaped}'",
        };
        DB::statement($sql);
    }

    /** Convenience: read existing, merge new keys in, write back -- one call. */
    public static function set(array $target, array $newKeys): void
    {
        self::apply($target, self::merge(self::read($target), $newKeys));
    }
}
