<?php

namespace Acorn\Console\CreateSystem;

use Exception;

class CommentShow extends CommentCommandBase
{
    protected static $defaultName = 'acorn:cs:comment-show';

    protected $signature = 'acorn:cs:comment-show
        {table : Table name, wildcards (*) allowed}
        {--column= : Narrow to one or more columns, wildcards allowed}
        {--fk : Show the FK CONSTRAINT comment for --column instead of the column comment}';

    protected $description = 'Show the current create-system YAML comment for one or more tables/columns/FKs (read-only, no confirmation needed)';

    public function handle()
    {
        try {
            $targets = $this->resolveTargets(
                $this->argument('table'),
                $this->option('column'),
                (bool) $this->option('fk'),
                requireConfirmation: false
            );
        } catch (Exception $e) {
            $this->error($e->getMessage());
            return 1;
        }

        foreach ($targets as $target) {
            $comment = $this->getExistingComment($target);
            $this->line('<info>' . $this->describeTarget($target) . '</info>');
            $this->line($comment ?: '  (no comment)');
            $this->line('');
        }

        return 0;
    }
}
