<?php

namespace Acorn;

use Illuminate\Database\Query\Grammars\PostgresGrammar as PostgresGrammarBase;
use Illuminate\Database\Query\Builder as BaseBuilder;

class PostgresGrammar extends PostgresGrammarBase
{
    public function compileInsertOrAdopt(BaseBuilder $query, array $values, string|array $uniqueBy = 'code')
    {
        $uniqueByClause = (is_array($uniqueBy)
            ? $this->columnize($uniqueBy)
            : $uniqueBy
        );
        $uniqueByClause = "($uniqueByClause)";
        $insertSQL      = $this->compileInsert($query, $values);
        return "$insertSQL ON CONFLICT $uniqueByClause DO NOTHING RETURNING *";
    }
}
