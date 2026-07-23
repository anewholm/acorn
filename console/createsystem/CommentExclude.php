<?php

namespace Acorn\Console\CreateSystem;

use DB;
use Winter\Storm\Support\Str;
use Exception;

/**
 * Sets field-exclude/column-exclude on an FK constraint (suppressing the
 * REVERSE relation-manager on the REFERENCED table's own form -- e.g.
 * hiding "Consumables using this Colour" from pa_colours' edit screen)
 * and, where possible, live-patches the already-generated fields.yaml /
 * columns.yaml so the change is visible immediately without waiting for a
 * full create:plugin regen.
 *
 * Live patching works because every relation-manager field/column entry
 * create-system generates embeds its own FK constraint name inside its
 * debug block (create-system-db-lang-path), e.g.:
 *   tables.domain.data.fifteen.commerce_pa_card_strips.foreignkeys.fifteen_commerce_pa_card_strips_pa_wall_type_id_fkey
 * so the matching entry can be found by searching for that constraint name
 * as a substring, without needing to reconstruct create-system's own
 * relation-naming algorithm.
 *
 * Only the FK-constraint (reverse) case is live-patched -- the forward
 * case (excluding the FK's own lookup field on the referencing table) only
 * updates the DB comment; the field-key-naming convention there wasn't
 * reliably determinable from generated output the same way, so it always
 * needs a create:plugin regen.
 */
class CommentExclude extends CommentCommandBase
{
    protected static $defaultName = 'acorn:cs:exclude';

    protected $signature = 'acorn:cs:exclude
        {table : Table name owning the FK column, wildcards (*) allowed}
        {--column= : FK column name, wildcards allowed}
        {--no-live : Only update the DB comment, skip attempting to live-patch fields.yaml/columns.yaml}';

    protected $description = 'Set field-exclude/column-exclude on FK constraint(s) -- suppresses the reverse relation-manager on the referenced table -- and live-patches its fields.yaml/columns.yaml where possible';

    public function handle()
    {
        try {
            $targets = $this->resolveTargets(
                $this->argument('table'),
                $this->option('column'),
                fk: true
            );
        } catch (Exception $e) {
            $this->error($e->getMessage());
            return 1;
        }

        foreach ($targets as $target) {
            $existing = $this->getExistingComment($target);
            $merged = $this->mergeComment($existing, ['field-exclude' => true, 'column-exclude' => true]);
            $this->applyComment($target, $merged);
            $this->info('DB comment updated: ' . $this->describeTarget($target));

            if (!$this->option('no-live')) {
                $this->attemptLivePatch($target);
            }
        }

        return 0;
    }

    protected function attemptLivePatch(array $target): void
    {
        $referencedTable = DB::selectOne(
            "SELECT cf.relname AS table_name, nf.nspname AS schema_name
             FROM pg_constraint c
             JOIN pg_class cf ON cf.oid = c.confrelid
             JOIN pg_namespace nf ON nf.oid = cf.relnamespace
             WHERE c.conname = ?",
            [$target['constraint']]
        );

        if (!$referencedTable) {
            $this->warn("  Could not determine referenced table for {$target['constraint']}, skipping live patch.");
            return;
        }

        $modelKey = $this->modelKeyForTable($referencedTable->table_name);
        $patched = false;

        foreach (['fields.yaml', 'columns.yaml'] as $file) {
            $path = base_path("plugins/fifteen/commerce/models/{$modelKey}/{$file}");
            if (!file_exists($path)) {
                continue;
            }
            if ($this->stripMatchingEntry($path, $target['constraint'])) {
                $this->info("  Live-patched {$modelKey}/{$file}");
                $patched = true;
            }
        }

        if (!$patched) {
            $this->line("  No matching entry found in {$modelKey}'s generated YAML (already absent, or needs a create:plugin run).");
        }
    }

    protected function modelKeyForTable(string $table): string
    {
        $subName = preg_replace('/^fifteen_commerce_/', '', $table);
        return strtolower(Str::studly(Str::singular($subName)));
    }

    /**
     * Remove the entry (at any fields: nesting depth -- top-level fields:,
     * tabs.fields:, secondaryTabs.fields:, tertiaryTabs.fields:, etc.)
     * whose block mentions the given FK constraint name.
     *
     * Deliberately NOT a parse-to-array-then-redump: Symfony's YAML dumper
     * silently drops every '#' comment on a round trip (confirmed by
     * testing against a real generated file) and re-quotes scalars that
     * didn't need it, corrupting create-system's own generated
     * documentation. Instead this does a surgical, indentation-aware line
     * removal: track the ancestor key chain via an indent-keyed stack, and
     * only remove a block whose *immediate* parent key is literally
     * "fields" -- everything else in the file stays byte-identical.
     */
    protected function stripMatchingEntry(string $path, string $constraintName): bool
    {
        $lines = file($path, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            return false;
        }
        $total = count($lines);
        $output = [];
        $removed = false;
        $stack = []; // [[indent, key], ...] ancestor chain by indentation

        $i = 0;
        while ($i < $total) {
            $line = $lines[$i];
            $trimmed = ltrim($line);

            // A bare "key:" (optionally with a trailing comment) line --
            // never matches literal-block HTML content, which always has
            // other characters before/after any colon on the line.
            if ($trimmed !== '' && preg_match('/^([A-Za-z0-9_.]+):[ \t]*(#.*)?$/', $trimmed, $m)) {
                $indent = strlen($line) - strlen($trimmed);
                $key = $m[1];

                while (!empty($stack) && end($stack)[0] >= $indent) {
                    array_pop($stack);
                }
                $parentKey = empty($stack) ? null : end($stack)[1];

                if ($parentKey === 'fields') {
                    $end = $this->blockEnd($lines, $i + 1, $indent, $total);
                    $blockText = implode("\n", array_slice($lines, $i, $end - $i));
                    if (str_contains($blockText, $constraintName)) {
                        $removed = true;
                        $i = $end;
                        continue; // skip entirely: don't output, don't push to stack
                    }
                }

                $stack[] = [$indent, $key];
            }

            $output[] = $line;
            $i++;
        }

        if ($removed) {
            file_put_contents($path, implode("\n", $output) . "\n");
        }

        return $removed;
    }

    /** First line index >= $from whose indentation is <= $indent, ignoring blank lines. */
    protected function blockEnd(array $lines, int $from, int $indent, int $total): int
    {
        $j = $from;
        while ($j < $total) {
            $candidate = $lines[$j];
            if (trim($candidate) === '') {
                $j++;
                continue;
            }
            $candidateIndent = strlen($candidate) - strlen(ltrim($candidate));
            if ($candidateIndent <= $indent) {
                break;
            }
            $j++;
        }
        return $j;
    }
}
