<?php namespace Acorn;

use Winter\Storm\Database\Updates\Migration as StormMigration;
use Symfony\Component\HttpFoundation\File\File;
use Symfony\Component\HttpFoundation\File\Exception\FileNotFoundException;
use DB;
use Doctrine\DBAL\Schema\View;
use Exception;

class Migration extends StormMigration
{
    use Traits\PathsHelper;

    // --------------------------------------- Semantic
    public static function setTableComment($table, $comment): bool
    {
        // The yaml files normalize space
        // So spaces are pre-transformed to &nbsp;
        // here, we transform back
        $commentEscaped = str_replace("\xc2\xa0",' ', $comment);
        $commentEscaped = str_replace("'",'\\\'', $commentEscaped);
        return DB::statement("COMMENT ON TABLE $table IS '$commentEscaped'");
    }

    public static function setColumnComment($table, $column, $comment): bool
    {
        // The yaml files normalize space
        // So spaces are pre-transformed to &nbsp;
        // here, we transform back
        $commentEscaped = str_replace("\xc2\xa0",' ', $comment);
        $commentEscaped = str_replace("'",'\\\'', $commentEscaped);
        return DB::statement("COMMENT ON COLUMN $table.$column IS '$commentEscaped'");
    }

    public static function setForeignKeyComment($table, $foreignkey, $comment): bool
    {
        // The yaml files normalize space
        // So spaces are pre-transformed to &nbsp;
        // here, we transform back
        $commentEscaped = str_replace("\xc2\xa0",' ', $comment);
        $commentEscaped = str_replace("'",'\\\'', $commentEscaped);
        return DB::statement("COMMENT ON CONSTRAINT $foreignkey ON $table IS '$commentEscaped'");
    }

    // --------------------------------------- Replication
    public function isCentralPublisher(): bool
    {
        return (gethostname() == 'acornssociated-local'
            || DB::connection()->getConfig('is_central_publisher') == true
        );
    }

    public function truncateDatabase(string $tablePrefix): bool
    {
        DB::unprepared("select fn_acorn_truncate_database('%', '$tablePrefix%')");
        return TRUE;
    }

    public function resetSequences(string $tablePrefix): bool
    {
        DB::unprepared("select fn_acorn_reset_sequences('%', '$tablePrefix%')");
        return TRUE;
    }

    public function cleanDatabase(string $tablePrefix)
    {
        $this->truncateDatabase($tablePrefix);
        $this->resetSequences($tablePrefix);
        return TRUE;
    }

    public function setTableTypeContent(string $tableName)
    {
        // This is for legacy singular named tables that are the target of new FKs and create-system
        DB::unprepared("COMMENT ON TABLE $tableName IS 'table-type: content'");
    }

    public function setPackageTypePlugin(string $tableName)
    {
        // This is for legacy singular named tables that are the target of new FKs and create-system
        DB::unprepared("COMMENT ON TABLE $tableName IS 'package-type: plugin\ntable-type: content'");
    }

    public function tableCounts(?string $tableMask = NULL): array
    {
        if (!$tableMask) $tableMask = $this->tableMask();
        return DB::select("select * from fn_acorn_table_counts('public') where \"table\" like('$tableMask')");
    }

    public function tableNames(?string $tabletableMask = NULL): array
    {
        return array_column($this->tableCounts($tabletableMask), 'table');
    }

    public function refreshSubscriptionTo(array|string $subscriberInfo): bool
    {
        // TODO: ALTER SUBSCRIPTION sub_acorn_lojistiks_all_tables REFRESH PUBLICATION WITH (COPY_DATA=false);
        throw new Exception('Not complete');
        return TRUE;
    }

    public function subscribeTo(array|string $subscriberInfo = 'replication_publisher'): bool
    {
        // ------------------------------------------------- Config
        $hostname    = gethostname();
        $tablePrefix = $this->tablePrefix();
        if (is_string($subscriberInfo)) $subscriberInfo = [
            'connection'   => $subscriberInfo,
        ];
        // Programmatic sub/pub naming
        if (!isset($subscriberInfo['table_prefix'])) $subscriberInfo['table_prefix'] = $tablePrefix; // acorn_lojistiks_
        if (!isset($subscriberInfo['publication']))  $subscriberInfo['publication']  = "pub_$subscriberInfo[table_prefix]tables"; // pub_acorn_lojistiks_tables
        if (!isset($subscriberInfo['subscription'])) $subscriberInfo['subscription'] = "sub_$subscriberInfo[table_prefix]tables";
        if (!isset($subscriberInfo['slotname']))     $subscriberInfo['slotname']     = "slot_$subscriberInfo[table_prefix]tables_$hostname";
        if (!isset($subscriberInfo['copy_data']))    $subscriberInfo['copy_data']    = true;
        if (!isset($subscriberInfo['streaming']))    $subscriberInfo['streaming']    = true;

        // ------------------------------------------------- Replication publisher DB connection
        $publisherConnection = config("database.connections.$subscriberInfo[connection]");
        // Inherit main connection settings
        foreach (DB::connection()->getConfig() as $name => $value) {
            if ($name != 'subscribe_to') {
                if (!isset($publisherConnection[$name])) $publisherConnection[$name] = $value;
            }
        }
        if (!isset($publisherConnection['sslmode'])) $publisherConnection['sslmode'] = 'disable';
        print("\t\t\tChecking the connection to $publisherConnection[host]:$publisherConnection[port]\n");
        DB::connection($subscriberInfo['connection'])->select('select 1');


        // TODO: ------------------------------------------------- Check / create publication exists
        // print("\t\t\t\tChecking publication on $subscriberInfo[connection]\n");
        print("\t\t\tSubscribing to publication $subscriberInfo[publication]\n");

        // Always cleaning is necessary before copy_data runs
        if ($subscriberInfo['copy_data']) {
            print("\t\t\t\tCleaning database\n");
            $this->cleanDatabase($subscriberInfo['table_prefix']);
        }

        /* ------------------------------------------------- Create the subscription
         * https://postgrespro.com/docs/postgresql/16/sql-altersubscription
         * By default, PG waits for the WAL log to fill (16MB) before updating subscribers
         * Streaming ships each new WAL log entry (DB change) immediately
         * Replication slots provide an automated way to ensure that the primary does not remove WAL segments until they have been received by all standbys, and that the primary does not remove rows which could cause a recovery conflict even when the standby is disconnected.
         * The initial data in existing subscribed tables are snapshotted and copied in a parallel instance of a special kind of apply process. This process will create its own replication slot and copy the existing data. As soon as the copy is finished the table contents will become visible to other backends. Once existing data is copied, the worker enters synchronization mode, which ensures that the table is brought up to a synchronized state with the main apply process by streaming any changes that happened during the initial data copy using standard logical replication. During this synchronization phase, the changes are applied and committed in the same order as they happened on the publisher. Once synchronization is done, control of the replication of the table is given back to the main apply process where replication continues as normal.
         * Binary requires exact column data type matching, whereas non-binary, for example, allows integer to be mapped to bigint
         */
        $streaming = ($subscriberInfo['streaming'] ? 'True' : 'False');
        $copyData  = ($subscriberInfo['copy_data'] ? 'true' : 'false');
        print("\t\t\t\tDropping existing subscription (if exists)\n");
        DB::unprepared("DROP SUBSCRIPTION IF EXISTS $subscriberInfo[subscription]");

        print("\t\t\t\tCreating subscription\n");
        $SQL = <<<SQL
            CREATE SUBSCRIPTION $subscriberInfo[subscription]
                CONNECTION 'host=$publisherConnection[host] port=$publisherConnection[port] dbname=$publisherConnection[database] user=$publisherConnection[username] password=$publisherConnection[password] sslmode=$publisherConnection[sslmode]'
                PUBLICATION $subscriberInfo[publication]
                WITH (
                    streaming = '$streaming',
                    create_slot = true,
                    slot_name = '$subscriberInfo[slotname]',
                    binary = false,
                    copy_data = $copyData,

                    connect = true,
                    enabled = true,
                    synchronous_commit = 'off',
                    two_phase = false,
                    disable_on_error = false,
                    run_as_owner = false,
                    password_required = true,
                    origin = 'any'
                );
SQL;
        DB::unprepared($SQL);

        // ------------------------------------------------- Bi-directional local publication
        print("\t\t\t\tDropping existing local publication (if exists)\n");
        DB::unprepared("DROP PUBLICATION IF EXISTS $subscriberInfo[publication]");

        print("\t\t\t\tCreating publication to $subscriberInfo[connection]\n");
        $pub_tables = implode(', ', $this->tableNames());
        $SQL = <<<SQL
            CREATE PUBLICATION $subscriberInfo[publication]
                FOR TABLE $pub_tables
                WITH (publish = 'insert, update, delete, truncate', publish_via_partition_root = false);
SQL;
        DB::unprepared($SQL);

        // ------------------------------------------------- Create subscription on server
        // print("\t\t\t\tCreating subscription on $subscriberInfo[connection]\n");
        $SQL = <<<SQL
            CREATE SUBSCRIPTION $subscriberInfo[subscription]
            CONNECTION 'host=192.168.88.252 port=5433 dbname=acornlojistiks user=sz password=xxxxxx sslmode=disable'
            PUBLICATION $subscriberInfo[publication]
            WITH (
                streaming = 'True',
                slot_name = 'sub_acorn_lojistiks_all_tables_laptop',
                copy_data = false,
            );
SQL;
        // TODO: DB::connection($subscriberInfo[connection])->unprepared($SQL);

        // ------------------------------------------------- Asynchronous results!
        // Now copy_data will run, creating an additional temporary slot on the publisher during operation
        // All data will come down
        // Local Sequences WILL NOT be updated by the copy_data copies
        // UUIDs are recommended

        return TRUE;
    }

    public function setReplicaIdentity($table, array $fields = ['id'], string $indexType = 'btree')
    {
        $baseName     = str_replace('.', '_', $table);
        $indexName    = "dr_${baseName}_replica_identity";
        $fieldsString = implode(',', $fields);
        DB::unprepared(<<<SQL
            CREATE UNIQUE INDEX $indexName ON ${table} USING $indexType ($fieldsString);
            ALTER TABLE ONLY ${table} REPLICA IDENTITY USING INDEX $indexName;
SQL
        );
    }

    // --------------------------------------- Up & Down from SQL files
    public function up()
    {
        print("\n");
        $fqClass = $this->fullyQualifiedClassName();

        // Schema
        print("\t\t\tRunning SQL scripts for $fqClass\n");
        $this->runSQL('pre-up'); // Custom written
        $this->runSQL('up');     // Generated by update_sqls
        $this->runSQL('dependencies'); // Changes to other plugins

        // Initial data
        $subscribeTo = DB::connection()->getConfig('subscribe_to');
        if ($subscribeTo) $this->subscribeTo($subscribeTo);
        else $this->runSQL('seed');

        $this->runSQL('post-up'); // Custom written
    }

    public function down()
    {
        print("\n");
        $this->runSQL('down'); // Generated by update_sqls
    }

    public function runSQL(string $sqlFilename): string
    {
        $sql                 = NULL;
        $pluginPathRelative  = $this->pluginPathRelative();
        $sqlFilepathRelative = "$pluginPathRelative/updates/$sqlFilename.sql";

        try {
            $file = new File($sqlFilepathRelative, TRUE);
            $sql  = $file->getContent();
        } catch (FileNotFoundException $ex) {}

        if ($sql && trim($sql)) {
            print("\t\t\t$sqlFilename.sql ");
            $yn = 'y'; // readline("Execute $sqlFilepathRelative (y)?");
            if ($yn == 'n') {
                print(" USER CANCELLED\n");
            } else {
                DB::unprepared($sql);
                print(" DONE\n");
            }
        }

        return $sqlFilepathRelative;
    }

    // ------------------------------------------ Extended table management
    // TODO: Make these methods on an Acorn Table Class
    public function dropIfExistsCascade($table)
    {
        DB::unprepared("drop table if exists $table cascade");
    }

    public function dropCascade($table)
    {
        $this->dropIfExistsCascade($table);
    }

    public function dropForeignIfExists($table, $foreignKey)
    {
        DB::unprepared("SELECT exists(select * FROM information_schema.table_constraints WHERE constraint_name='$foreignKey' AND table_name='$table')");
    }

    // ------------------------------------------ Extended Objects
    public function createExtension(string $name)
    {
        DB::unprepared("create extension if not exists $name;");
    }

    public function createView(string $name, string $body)
    {
        DB::getDoctrineSchemaManager()->createView(new View($name, $body));
    }

    public function createFunction(string $name, array $parameters, string $returnType, array $declares, string $body, ?string $language = 'plpgsql', ?array $modifiers = [])
    {
        // Function name must start with fn_<author>_<plugin>_
        if (!$this->hasFunctionPrefix($name)) throw new Exception("Function $name does not have correct prefix fn_<author>_<plugin>_");
        $BODY = '$BODY$';
        $parametersString = implode(',', $parameters);
        $declareString    = implode(";\n", $declares);
        $modifiersString  = implode(' ', $modifiers);
        if ($declareString) $declareString = "declare\n$declareString;";
        if ($language == 'plpgsql') $body = "begin\n$body\nend;";
        DB::unprepared(<<<SQL
            create or replace function $name($parametersString) returns $returnType
            as $BODY
            $declareString
            $body
            $BODY language $language $modifiersString;
SQL
        );
    }

    public function createTrigger(string $name, string $stage, string $action, string $table, bool $forEachRow, string $function, bool $always = FALSE)
    {
        // Trigger name must start with tr_<author>_<plugin>_
        if (!$this->hasTriggerPrefix($name)) throw new Exception("Trigger $name does not have correct prefix tr_<author>_<plugin>_");
        $forEachRowString = ($forEachRow ? 'FOR EACH ROW' : '');
        DB::unprepared(<<<SQL
            CREATE OR REPLACE TRIGGER $name
                $stage $action
                ON $table
                $forEachRowString
                EXECUTE FUNCTION $function();
SQL
        );
        // ALWAYS is used also for replication
				if ($always) DB::unprepared("'ALTER TABLE IF EXISTS $table ENABLE ALWAYS TRIGGER $name");
    }

    public function createAggregate(string $name, string $function, string $parameterType = 'anyelement', string $parallel = 'safe')
    {
        // Trigger name must start with agg_<author>_<plugin>_
        if (!$this->hasAggregatePrefix($name)) throw new Exception("Aggregate $name does not have correct prefix agg_<author>_<plugin>_");
        DB::unprepared(<<<SQL
            CREATE AGGREGATE $name($parameterType) (
                SFUNC = $function,
                STYPE = $parameterType,
                PARALLEL = $parallel
            );
SQL
        );
    }

    public function createFunctionAndTrigger(string $baseName, string $stage, string $action, string $table, bool $forEachRow, array $declares, string $body, ?string $language = 'plpgsql', bool $always = FALSE)
    {
        // Base name must be in the form <author>_<plugin>_*
        $functionName = "fn_$baseName";
        $this->createFunction($functionName, [], 'trigger', $declares, $body, $language);
        $this->createTrigger("tr_$baseName", $stage, $action, $table, $forEachRow, $functionName, $always);
    }

    public function createFunctionAndAggregate(string $baseName, array $parameters, string $body, ?array $declares = [], ?string $parameterType = 'anyelement', ?string $parallel = 'safe', ?string $language = 'sql', ?array $modifiers = ['IMMUTABLE', 'STRICT', 'PARALLEL', 'SAFE'])
    {
        // Base name must be in the form <author>_<plugin>_*
        $functionName = "fn_$baseName";
        $this->createFunction($functionName, $parameters, $parameterType, $declares, $body, $language, $modifiers);
        $this->createAggregate("agg_$baseName", $functionName, $parameterType, $parallel);
    }

    public function addUniqueConstraint(string $table, array $columns, string $name = NULL): string
    {
        if (is_null($name)) $name = "{$table}_" . implode('_', $columns);
        $exists = DB::selectOne('SELECT 1 FROM pg_constraint WHERE conname = ?', [$name]);
        if (!$exists) {
            $columnString = implode(', ', $columns);
            DB::unprepared("ALTER TABLE IF EXISTS $table ADD CONSTRAINT $name UNIQUE ($columnString);");
        }

        return $name;
    }

    // ------------------------------------------ Standard triggers / fields
    public function serverField() {
        // TODO: server_id field and trigger
    }

    public function createdByUserField() {
        // TODO: created_by_user_id field and trigger
    }

    public function updatedByUserField() {
        // TODO: created_by_user_id field and trigger
    }

    // ------------------------------------------ Extended Fields
    // TODO: Make these methods on an Acorn Table Class
    public function setFunctionDefault(string $table, string $column, string $function)
    {
        DB::unprepared("alter table \"$table\" alter column \"$column\" set default $function()");
    }

    public function generated(string $table, string $column, string $function, string $type = 'character varying(1024)')
    {
        DB::unprepared("ALTER TABLE $table ADD COLUMN $column $type GENERATED ALWAYS AS ($function) STORED");
    }

    public function interval(string $table, string $column, ?bool $nullable = FALSE)
    {
        $null = ($nullable ? '' : 'NOT NULL');
        DB::unprepared("alter table $table add column $column interval $null;");
    }

    public function intervalWithDefault(string $table, string $column, ?bool $nullable = FALSE, $default = 0)
    {
        $null = ($nullable ? '' : 'NOT NULL');
        DB::unprepared("alter table $table add column $column interval $null default '00:00:00';");
    }

    public function integerArray(string $table, string $column, ?bool $nullable = FALSE)
    {
        $null = ($nullable ? '' : 'NOT NULL');
        DB::unprepared("alter table $table add column $column integer[] $null;");
    }

    public function dateRange(string $table, string $column, bool $nullable = false, string $default = 'daterange(CURRENT_DATE, NULL)'): void
    {
        $null = $nullable ? '' : 'NOT NULL';
        DB::unprepared("ALTER TABLE $table ADD COLUMN $column daterange $null DEFAULT $default");
    }

    public function addGistIndex(string $table, array $columns, ?string $name = null): string
    {
        $this->createExtension('btree_gist');
        $cols = implode(', ', $columns);
        $name = $name ?? $table . '_' . implode('_', array_map(fn($c) => preg_replace('/[^a-zA-Z0-9]/', '_', $c), $columns)) . '_gist';
        DB::unprepared("CREATE INDEX $name ON $table USING GIST ($cols)");
        return $name;
    }

    public function addExcludeConstraint(string $table, array $columnOperators, string $name): void
    {
        $this->createExtension('btree_gist');
        $cols = implode(', ', $columnOperators);
        DB::unprepared("ALTER TABLE $table ADD CONSTRAINT $name EXCLUDE USING GIST ($cols)");
    }

    /**
     * Add a temporal date-range versioning pattern to a membership-style table:
     *   - daterange period column (NOT NULL, open-ended default = active)
     *   - GiST index on (groupColumn, period) for fast point-in-time queries
     *   - EXCLUDE constraint preventing overlapping periods for the same (user, group) pair
     *
     * Supports leave-and-rejoin: sequential non-overlapping rows are allowed.
     */
    public function addDateRangeVersioning(
        string $table,
        bool $addCurrentIndex = TRUE,
        string $periodColumn = 'period',
        string $userColumn   = 'user_id',
        string $groupColumn  = 'user_group_id'
    ): void {
        $this->dateRange($table, $periodColumn);
        $this->addGistIndex($table, [$groupColumn, $periodColumn]);
        $this->addExcludeConstraint(
            $table,
            ["$userColumn WITH =", "$groupColumn WITH =", "$periodColumn WITH &&"],
            "{$table}_no_overlap"
        );

        if ($addCurrentIndex) {
            // Fast lookup: current members per group (open-ended upper bound)
            DB::unprepared(
                "CREATE INDEX {$table}_current ON $table ($groupColumn) WHERE upper_inf($periodColumn)"
            );
        }

    }
}
