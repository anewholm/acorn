<?php namespace Acorn\Traits;

use Anthropic\Client;
use Anthropic\Lib\Tools\BetaRunnableTool;

// Pushed up from Fifteen\Relay\Classes to Acorn\Traits (2026-08-24) --
// askClaude() has no Relay-specific logic at all, so it belongs at the
// generic framework level any Acorn-based project can use, not folded
// into the Relay plugin it was first built for. See
// Fifteen\Relay\Classes\UsesAddress::resolveViaExternalServiceCall()'s
// own docblock for its first real caller.
//
// Genuinely last resort wherever it's used -- an LLM call is slow,
// costs money, and answers non-deterministically compared to every
// other resolution mechanism in this codebase. askClaude() is meant to
// be reused anywhere in the application that needs a typed answer to a
// research/judgement question an ordinary DB lookup can't settle on its
// own -- deliberately generic, not address-specific.
trait Claude
{
    // The one public method. $requiredResponseFormat is a raw JSON Schema
    // (object root, `additionalProperties: false`, every field in
    // `required` -- the same shape structured-outputs strict tool
    // schemas need, see shared/tool-use-concepts.md's Structured Outputs
    // section) describing exactly what shape the answer must take, e.g.
    //   ['type' => 'object',
    //    'properties' => ['region_id' => ['type' => ['integer', 'null']]],
    //    'required' => ['region_id'],
    //    'additionalProperties' => false]
    // Returns the decoded answer array matching that schema, or null if:
    // CLAUDE_API_KEY isn't set (feature disabled -- same no-op contract
    // as UsesAddress::resolveViaGoogleGeocode()), the API/network fails,
    // or Claude never settles on an answer within the iteration cap.
    // Never throws -- an unreachable/erroring external service should
    // degrade the caller back to "couldn't determine," not blow up
    // whatever's calling this.
    //
    // $allowDbAccess opts in to a `query_database` tool that lets Claude
    // run its own read-only SELECT statements against this application's
    // database while it works out the answer -- only offered at all when
    // BOTH this is true AND CLAUDE_READ_ONLY_USER is configured. That
    // role's grants (SELECT only, no INSERT/UPDATE/DELETE/DDL, enforced
    // by Postgres itself) are the real safety boundary; the SQL-shape
    // checks in runReadOnlyQuery() below are defense in depth on top of
    // that, not instead of it. A caller that already has everything
    // Claude needs in $context (e.g. UsesAddress.php's address-
    // resolution use case, which already knows its full candidate set
    // before asking) should leave this false -- faster, cheaper, and
    // Claude can't go off and query something unrelated to the question
    // asked.
    public function askClaude(string $context, string $question, array $requiredResponseFormat, bool $allowDbAccess = false): ?array
    {
        $apiKey = env('CLAUDE_API_KEY');
        if (!$apiKey) return null;

        $dbUser = env('CLAUDE_READ_ONLY_USER');
        $dbPass = env('CLAUDE_READ_ONLY_PASSWORD');
        $dbAccessGranted = $allowDbAccess && $dbUser;

        $cacheKey = hash('sha256', json_encode([$context, $question, $requiredResponseFormat, $dbAccessGranted]));
        $cached = \Db::table('acorn_claude_cache')->where('cache_key', $cacheKey)->first();
        if ($cached) {
            return $cached->response ? json_decode($cached->response, true) : null;
        }

        // provide_answer is the vehicle for a guaranteed-typed final
        // result -- Claude is told to call it exactly once, when ready,
        // with input conforming to $requiredResponseFormat. Its run
        // closure never actually executes: the loop below breaks as
        // soon as this tool_use block is seen, before the runner would
        // call it. strict: true (alongside name/description/inputSchema,
        // NOT nested under it) guarantees the input validates against
        // the schema -- no parsing-and-hoping.
        $tools = [
            new BetaRunnableTool(
                definition: [
                    'name'        => 'provide_answer',
                    'description' => 'Call this exactly once, when you have determined the final answer (or determined that no answer can be found -- use null/empty values as the schema allows). This ends the conversation.',
                    'inputSchema' => $requiredResponseFormat,
                    'strict'      => true,
                ],
                run: fn (array $input) => null,
            ),
        ];

        if ($dbAccessGranted) {
            $tools[] = new BetaRunnableTool(
                definition: [
                    'name'        => 'query_database',
                    'description' => 'Run a single read-only SQL SELECT statement against the application database to help answer the question. Returns up to 50 rows as JSON. Use this only if the context given does not already contain what you need.',
                    'inputSchema' => [
                        'type'                 => 'object',
                        'properties'           => ['sql' => ['type' => 'string', 'description' => 'A single SELECT statement.']],
                        'required'             => ['sql'],
                        'additionalProperties' => false,
                    ],
                    'strict' => true,
                ],
                run: fn (array $input) => self::runReadOnlyQuery($input['sql'] ?? '', $dbUser, $dbPass),
            );
        }

        $answer = null;
        try {
            $client = new Client(apiKey: $apiKey);
            $runner = $client->beta->messages->toolRunner(
                model: 'claude-opus-5',
                maxTokens: 4096,
                messages: [['role' => 'user', 'content' => "Context:\n{$context}\n\nQuestion: {$question}"]],
                tools: $tools,
                // This installed SDK version's toolRunner() has no named
                // $system param -- it only takes maxTokens/messages/model/
                // tools/maxIterations, with everything else forwarded
                // verbatim to each messages.create() call via extraParams.
                extraParams: ['system' => 'You are a data-resolution assistant embedded in an application backend, consulted only when ordinary lookups could not settle a question on their own. Answer strictly from the context given'
                    . ($dbAccessGranted ? ', using the query_database tool if genuinely needed' : '')
                    . '. Call provide_answer exactly once with your answer.'],
            );

            $iterations = 0;
            foreach ($runner as $message) {
                foreach ($message->content as $block) {
                    if ($block->type === 'tool_use' && $block->name === 'provide_answer') {
                        $answer = $block->input;
                        break 2;
                    }
                }
                // Defense in depth against an unbounded query_database
                // loop that never reaches an answer -- not expected to
                // matter in normal operation.
                if (++$iterations >= 6) break;
            }
        } catch (\Throwable $e) {
            $answer = null;
        }

        \Db::table('acorn_claude_cache')->insert([
            'cache_key'       => $cacheKey,
            'context'         => $context,
            'question'        => $question,
            'response_format' => json_encode($requiredResponseFormat),
            'response'        => $answer !== null ? json_encode($answer) : null,
            'created_at'      => now(),
        ]);

        return $answer;
    }

    // The DB role's own grants (SELECT only, no writes/DDL -- see this
    // file's callsite comment) are the real control here. Everything
    // below is defense in depth on top of that, not a substitute for it:
    // rejecting anything not starting with SELECT, rejecting a second
    // statement (a bare semicolon check -- deliberately not trying to
    // fully parse SQL, since the DB role's grants are what actually
    // matters), a 5s statement_timeout set on the role itself (not
    // repeated here), and a hard 50-row cap on what comes back so a
    // broad SELECT can't flood the conversation.
    //
    // Goes through Laravel's own connection manager rather than a raw
    // PDO handle, registering a throwaway connection that clones the
    // app's own default connection config (host/port/database/driver --
    // whatever the app is actually configured for) and swaps in only
    // the read-only credentials. That way this generic trait never
    // hardcodes a database name, host, or driver -- it inherits whatever
    // the host application is already connected to.
    protected static function runReadOnlyQuery(string $sql, string $user, string $pass): string
    {
        $trimmed = rtrim(trim($sql), ';');
        if (!preg_match('/^select\s/i', $trimmed)) {
            return json_encode(['error' => 'Only a single SELECT statement is allowed.']);
        }
        if (str_contains($trimmed, ';')) {
            return json_encode(['error' => 'Only a single statement is allowed.']);
        }

        $connectionName = 'claude_readonly';
        $defaultConfig = config('database.connections.' . config('database.default'));
        config(["database.connections.{$connectionName}" => [
            ...$defaultConfig,
            'username' => $user,
            'password' => $pass,
        ]]);

        try {
            $rows = \Db::connection($connectionName)->select($trimmed);
            return json_encode(array_slice($rows, 0, 50));
        } catch (\Throwable $e) {
            return json_encode(['error' => $e->getMessage()]);
        } finally {
            \Db::purge($connectionName);
        }
    }
}