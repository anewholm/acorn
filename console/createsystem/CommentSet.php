<?php

namespace Acorn\Console\CreateSystem;

use Exception;

class CommentSet extends CommentCommandBase
{
    protected static $defaultName = 'acorn:cs:comment-set';

    protected $signature = 'acorn:cs:comment-set
        {table : Table name, wildcards (*) allowed}
        {assignments* : One or more key=value pairs, e.g. field-comment="Material Type" tab-location=1. Dot paths nest, e.g. has-many-deep-settings.some_relation.field-exclude=true}
        {--column= : Target one or more columns instead of the table itself, wildcards allowed}
        {--fk : Target the FK CONSTRAINT for --column instead of the column (needed for reverse relation-manager settings)}';

    protected $description = 'Merge one or more YAML keys into a create-system comment on a table, column, or FK constraint. Always additive -- parses the existing comment and merges in, never overwrites.';

    public function handle()
    {
        try {
            $targets = $this->resolveTargets(
                $this->argument('table'),
                $this->option('column'),
                (bool) $this->option('fk')
            );
            $newKeys = $this->parseAssignments($this->argument('assignments'));
        } catch (Exception $e) {
            $this->error($e->getMessage());
            return 1;
        }

        foreach ($targets as $target) {
            $existing = $this->getExistingComment($target);
            $merged = $this->mergeComment($existing, $newKeys);
            $this->applyComment($target, $merged);
            $this->info('Updated ' . $this->describeTarget($target));
        }

        $this->line('');
        $this->comment('DB comment(s) updated. Run create:plugin to regenerate fields.yaml/columns.yaml.');

        return 0;
    }
}
